#!/usr/bin/env python3
"""python -m unittest discover -s tests  (from the repo root)"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import introspect, report                      # noqa: E402
from src.safety import audit, readonly, throttle        # noqa: E402
from src.safety.scope import Gate, OutOfScope           # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ReadOnly(unittest.TestCase):
    def test_write_verbs_refused(self):
        for method in ("PUT", "PATCH", "DELETE", "MERGE"):
            with self.assertRaises(readonly.ReadOnlyViolation):
                readonly.check(method, "management.azure.com", "/subscriptions")

    def test_get_allowed(self):
        readonly.check("GET", "management.azure.com", "/subscriptions?api-version=2020-01-01")

    def test_post_denied_by_default(self):
        with self.assertRaises(readonly.ReadOnlyViolation):
            readonly.check("POST", "management.azure.com", "/subscriptions/x/resourceGroups")

    def test_token_post_allowed(self):
        readonly.check("POST", "login.microsoftonline.com",
                       "/72f988bf-0000-0000-0000-000000000000/oauth2/v2.0/token")

    def test_listkeys_allowed_regeneratekey_not(self):
        base = "/subscriptions/a/resourceGroups/b/providers/Microsoft.Storage/storageAccounts/c"
        readonly.check("POST", "management.azure.com", base + "/listKeys")
        with self.assertRaises(readonly.ReadOnlyViolation):
            readonly.check("POST", "management.azure.com", base + "/regenerateKey")

    def test_runcommand_refused_even_as_get(self):
        # The action denylist runs before the verb check on purpose.
        with self.assertRaises(readonly.ReadOnlyViolation):
            readonly.check("GET", "management.azure.com", "/subscriptions/a/vm/runCommand")


class Scope(unittest.TestCase):
    def test_discovery_allowed_without_allowlist(self):
        Gate().check("https://management.azure.com/subscriptions?api-version=2020-01-01")

    def test_scoped_refused_without_allowlist(self):
        with self.assertRaises(OutOfScope):
            Gate().check("https://management.azure.com/subscriptions/"
                         "11111111-1111-1111-1111-111111111111/resourceGroups")

    def test_named_subscription_allowed(self):
        sub = "11111111-1111-1111-1111-111111111111"
        Gate(subscriptions=[sub]).check(
            "https://management.azure.com/subscriptions/%s/resourceGroups" % sub)

    def test_other_subscription_refused(self):
        with self.assertRaises(OutOfScope):
            Gate(subscriptions=["11111111-1111-1111-1111-111111111111"]).check(
                "https://management.azure.com/subscriptions/"
                "22222222-2222-2222-2222-222222222222/resourceGroups")

    def test_unlisted_tenant_refused(self):
        with self.assertRaises(OutOfScope):
            Gate(tenants=["11111111-1111-1111-1111-111111111111"]).check(
                "https://login.microsoftonline.com/"
                "22222222-2222-2222-2222-222222222222/oauth2/v2.0/token")


class Introspect(unittest.TestCase):
    SAS = ("sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2027-01-01T00:00:00Z"
           "&spr=https&sig=abc123")

    def test_sas_permissions(self):
        out = introspect.detect(self.SAS)
        self.assertEqual(out["kind"], "sas")
        self.assertEqual(out["permissions"], ["read", "list"])
        self.assertEqual(out["services"], ["blob", "file", "queue", "table"])

    def test_sas_expiry_is_utc(self):
        # Regression: mktime read the struct as local time and skewed this.
        self.assertEqual(introspect.detect(self.SAS)["expires_at"],
                         "2027-01-01T00:00:00Z")

    def test_sas_user_delegation_flagged(self):
        out = introspect.detect(self.SAS + "&skoid=aaaa-bbbb")
        self.assertTrue(out["user_delegation"])

    def test_jwt_roles_and_scopes(self):
        claims = {"aud": "https://graph.microsoft.com", "tid": "t", "oid": "o",
                  "appid": "a", "roles": ["Directory.Read.All"], "scp": "User.Read Mail.Send"}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        out = introspect.detect("eyJhbGciOiJSUzI1NiJ9.%s.sig" % payload)
        self.assertEqual(out["app_roles"], ["Directory.Read.All"])
        self.assertEqual(out["delegated_scopes"], ["User.Read", "Mail.Send"])
        self.assertEqual(len(out["declared"]), 3)

    def test_storage_connection_string(self):
        out = introspect.detect(
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=k==;"
            "EndpointSuffix=core.windows.net")
        self.assertEqual(out["service"], "storage")
        self.assertEqual(out["account"], "acct")

    def test_servicebus_connection_string(self):
        out = introspect.detect(
            "Endpoint=sb://ns.servicebus.windows.net/;"
            "SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=k=")
        self.assertEqual(out["service"], "servicebus/eventhub")
        self.assertEqual(out["key_name"], "RootManageSharedAccessKey")

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            introspect.detect("hello")


class Throttle(unittest.TestCase):
    def test_rate_is_clamped(self):
        self.assertGreaterEqual(throttle.Throttle(rps=500).gap, 1.0 / throttle.MAX_RPS)

    def test_host_gap_has_a_floor(self):
        self.assertGreaterEqual(throttle.Throttle(host_gap=0).host_gap, throttle.MIN_HOST_GAP)


class Audit(unittest.TestCase):
    def test_fingerprint_is_stable_and_not_reversible(self):
        fp = audit.fingerprint("hunter2")
        self.assertEqual(fp, audit.fingerprint("hunter2"))
        self.assertNotIn("hunter2", fp)
        self.assertEqual(len(fp), 16)

    def test_introspection_sends_nothing(self):
        # Stage 0 must stay offline; a request row here means it regressed.
        log = os.path.join(os.environ.get("TEMP", "/tmp"), "azure-reach-test-audit.jsonl")
        if os.path.exists(log):
            os.remove(log)
        a = audit.AuditLog(log, "azure-reach/test")
        introspect.detect(Introspect.SAS)
        a.close()
        with open(log, encoding="utf-8") as fh:
            events = [json.loads(line)["event"] for line in fh]
        self.assertNotIn("request", events)
        os.remove(log)


class Hygiene(unittest.TestCase):
    def test_no_crlf(self):
        # A \r in a shebang is fatal on Linux.
        bad = []
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for name in files:
                if name.endswith((".py", ".tf", ".md", ".sh")):
                    path = os.path.join(root, name)
                    with open(path, "rb") as fh:
                        if b"\r\n" in fh.read():
                            bad.append(os.path.relpath(path, REPO))
        self.assertEqual(bad, [], "CRLF line endings in: %s" % bad)

    def test_verdict_order_covers_every_verdict(self):
        verdicts = {report.VERIFIED, report.VERIFIED_NEGATIVE, report.NOT_TESTED,
                    report.ASSUMED, report.INCONCLUSIVE}
        self.assertEqual(set(report.ORDER), verdicts)


if __name__ == "__main__":
    unittest.main()


class DataPlaneHosts(unittest.TestCase):
    """A vault or blob endpoint carries no subscription id, so path checking is blind
    to it. Hosts have to be registered as they are discovered."""

    def test_unregistered_data_plane_host_refused(self):
        with self.assertRaises(OutOfScope):
            Gate().check("https://myvault.vault.azure.net/secrets?api-version=7.4")

    def test_registered_host_allowed(self):
        gate = Gate()
        gate.allow_host("myvault.vault.azure.net")
        gate.check("https://myvault.vault.azure.net/secrets?api-version=7.4")

    def test_registration_does_not_leak_to_siblings(self):
        gate = Gate()
        gate.allow_host("mine.blob.core.windows.net")
        with self.assertRaises(OutOfScope):
            gate.check("https://theirs.blob.core.windows.net/?comp=list")

    def test_control_plane_hosts_need_no_registration(self):
        Gate().check("https://graph.microsoft.com/v1.0/servicePrincipals")


class ArgvRedaction(unittest.TestCase):
    """argv is written to the audit log, so a secret passed on the command line
    must never survive the trip."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "cli", os.path.join(REPO, "azure-reach.py"))
        self.cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.cli)

    def test_separated_value_is_redacted(self):
        out = self.cli.safe_argv(["--client-secret", "hunter2", "--tenant", "t"])
        self.assertNotIn("hunter2", out)
        self.assertEqual(out, ["--client-secret", "<redacted>", "--tenant", "t"])

    def test_equals_form_is_redacted(self):
        out = self.cli.safe_argv(["--client-secret=hunter2"])
        self.assertNotIn("hunter2", " ".join(out))

    def test_cred_is_redacted_too(self):
        out = self.cli.safe_argv(["--cred", "AccountKey=abc123=="])
        self.assertNotIn("abc123", " ".join(out))

    def test_file_flags_are_kept(self):
        # A path is not a secret, and which file was used is worth recording.
        out = self.cli.safe_argv(["--client-secret-file", "secret.txt"])
        self.assertEqual(out, ["--client-secret-file", "secret.txt"])

    def test_ordinary_args_survive(self):
        argv = ["--tenant", "t", "--subscriptions", "a,b", "--json"]
        self.assertEqual(self.cli.safe_argv(argv), argv)
