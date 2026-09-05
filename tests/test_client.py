#!/usr/bin/env python3
"""Client tests against a local HTTP server. Nothing here touches Azure."""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.safety import readonly                              # noqa: E402
from src.safety.audit import AuditLog                        # noqa: E402
from src.safety.client import Client, Halt                   # noqa: E402
from src.safety.scope import Gate, OutOfScope                # noqa: E402
from src.safety.throttle import Throttle                     # noqa: E402

TMP = os.environ.get("TEMP", "/tmp")


class Handler(BaseHTTPRequestHandler):
    def _respond(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://example.com/elsewhere")
            self.end_headers()
            return
        if self.path.startswith("/forbidden"):
            body = json.dumps({"error": {"code": "AuthorizationFailed"}}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"ok": True, "method": self.command}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = _respond

    def log_message(self, *args):
        pass


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.log = os.path.join(TMP, "azure-reach-client-test.jsonl")
        if os.path.exists(self.log):
            os.remove(self.log)
        self.audit = AuditLog(self.log, "azure-reach/test")

    def tearDown(self):
        self.audit.close()
        if os.path.exists(self.log):
            os.remove(self.log)

    def build(self, gate=None, max_requests=500, stop_file=None):
        gate = gate or Gate()
        # Data-plane hosts must be registered, exactly as the probes do once they
        # find a resource inside an authorized subscription.
        gate.allow_host("127.0.0.1")
        return Client(self.audit, Throttle(rps=5, host_gap=0), gate,
                      "azure-reach/test", stop_file=stop_file, max_requests=max_requests)

    def url(self, path="/"):
        return "http://127.0.0.1:%d%s" % (self.port, path)

    def events(self):
        with open(self.log, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]

    # -- happy path ------------------------------------------------------

    def test_get_returns_parsed_json_and_is_logged(self):
        resp = self.build().request("GET", self.url("/thing"))
        self.assertEqual(resp.status, 200)
        self.assertTrue(resp.json()["ok"])
        sent = [e for e in self.events() if e["event"] == "request"]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], 200)

    def test_user_agent_is_ours(self):
        resp = self.build().request("GET", self.url("/thing"),
                                    headers={"X-Test": "1"})
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.audit.user_agent, "azure-reach/test")

    def test_403_is_a_result_not_an_exception(self):
        # VERIFIED NEGATIVE depends on this: the body usually names the role.
        resp = self.build().request("GET", self.url("/forbidden"))
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.json()["error"]["code"], "AuthorizationFailed")

    def test_redirects_are_not_followed(self):
        resp = self.build().request("GET", self.url("/redirect"))
        self.assertEqual(resp.status, 302)
        self.assertIn("example.com", resp.headers.get("Location", ""))

    # -- refusals --------------------------------------------------------

    def test_write_verb_refused_and_nothing_sent(self):
        client = self.build()
        with self.assertRaises(readonly.ReadOnlyViolation):
            client.request("PUT", self.url("/thing"))
        self.assertEqual(self.audit.request_count, 0)
        kinds = [e["event"] for e in self.events()]
        self.assertIn("refused", kinds)
        self.assertNotIn("request", kinds)

    def test_out_of_scope_refused_and_nothing_sent(self):
        client = self.build(gate=Gate(subscriptions=["11111111-1111-1111-1111-111111111111"]))
        with self.assertRaises(OutOfScope):
            client.request("GET", self.url(
                "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups"))
        self.assertEqual(self.audit.request_count, 0)

    def test_refusal_is_recorded_with_its_reason(self):
        client = self.build()
        with self.assertRaises(readonly.ReadOnlyViolation):
            client.request("DELETE", self.url("/thing"))
        refused = [e for e in self.events() if e["event"] == "refused"]
        self.assertEqual(len(refused), 1)
        self.assertIn("write verb", refused[0]["reason"])

    # -- limits ----------------------------------------------------------

    def test_budget_halts_the_run(self):
        client = self.build(max_requests=2)
        client.request("GET", self.url("/a"))
        client.request("GET", self.url("/b"))
        with self.assertRaises(Halt):
            client.request("GET", self.url("/c"))
        self.assertEqual(self.audit.request_count, 2)

    def test_kill_switch_halts_before_sending(self):
        stop = os.path.join(TMP, "azure-reach-STOP")
        open(stop, "w").close()
        try:
            with self.assertRaises(Halt):
                self.build(stop_file=stop).request("GET", self.url("/thing"))
            self.assertEqual(self.audit.request_count, 0)
        finally:
            os.remove(stop)

    def test_token_requests_counted_separately(self):
        client = self.build()
        client.request("GET", self.url("/oauth2/v2.0/token"))
        client.request("GET", self.url("/other"))
        self.assertEqual(self.audit.request_count, 2)
        self.assertEqual(self.audit.token_count, 1)

    def test_transport_failure_is_logged_then_raised(self):
        import urllib.error
        client = self.build()
        # Nothing listens on port 1 anywhere.
        with self.assertRaises(urllib.error.URLError):
            client.request("GET", "http://127.0.0.1:1/dead")
        failures = [e for e in self.events()
                    if e["event"] == "request" and e["status"] is None]
        self.assertEqual(len(failures), 1)
        self.assertIn("transport failure", failures[0]["note"])


if __name__ == "__main__":
    unittest.main()
