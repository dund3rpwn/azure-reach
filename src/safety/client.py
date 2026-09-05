#!/usr/bin/env python3
"""The only way this tool sends a request.

urllib rather than requests/msal/azure-sdk, because the SDKs transmit on your
behalf -- background token refresh, silent retries, fan-out paging -- and this
tool reports how many requests it sent. It also lets us own the User-Agent,
which Entra records next to the credential id in sign-in logs.
"""

import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from . import readonly
from .scope import OutOfScope


class Halt(Exception):
    """Budget exhausted or kill switch tripped."""


class Response:
    def __init__(self, status, headers, body, url, elapsed_ms):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url
        self.elapsed_ms = elapsed_ms

    def json(self):
        try:
            return json.loads(self.body) if self.body else None
        except ValueError:
            return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect across an auth boundary is a finding; following it turns an
    # interesting 302 into a boring 200 somewhere nobody authorized.
    def redirect_request(self, *args):
        return None


class Client:
    def __init__(self, audit, throttle, gate, user_agent, stop_file=None,
                 max_requests=500, timeout=20):
        self.audit = audit
        self.throttle = throttle
        self.gate = gate
        self.user_agent = user_agent
        self.stop_file = stop_file
        self.max_requests = max_requests
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(self, method, url, headers=None, body=None, pair_id=None,
                control=False, note=None, anonymous=False):
        # Checked per request, not per host: a run that needs stopping needs
        # stopping now.
        if self.stop_file and os.path.exists(self.stop_file):
            raise Halt("kill switch present: %s" % self.stop_file)
        if self.audit.request_count >= self.max_requests:
            raise Halt("request budget of %d exhausted" % self.max_requests)

        parts = urlsplit(url)
        try:
            readonly.check(method, parts.hostname or "", parts.path or "/")
            self.gate.check(url)
        except (readonly.ReadOnlyViolation, OutOfScope) as exc:
            # Log refusals too, so the log can answer "did you touch X".
            self.audit.refused(method, url, str(exc))
            raise

        hdrs = {"User-Agent": self.user_agent, "Accept": "application/json"}
        hdrs.update(headers or {})
        if anonymous:
            # Positive control for public exposure. Stripping here rather than
            # trusting every caller to omit it means one credentialled header
            # cannot quietly turn the control into a normal authenticated read.
            hdrs.pop("Authorization", None)
            note = "anonymous: %s" % (note or "control")
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            body = body.encode()

        self.throttle.wait(parts.hostname or "")
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        started = time.monotonic()

        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                resp = Response(r.status, dict(r.headers), r.read(), url,
                                int((time.monotonic() - started) * 1000))
        except urllib.error.HTTPError as exc:
            # A 403 is a result, not an error -- it is how a permission is
            # proven absent, and the body usually names the missing role.
            resp = Response(exc.code, dict(exc.headers or {}), exc.read(), url,
                            int((time.monotonic() - started) * 1000))
        except urllib.error.URLError as exc:
            self.audit.request(method, url, None, pair_id=pair_id, control=control,
                               note="transport failure: %s" % exc.reason)
            raise

        self.audit.request(method, url, resp.status, pair_id=pair_id, control=control,
                           note=note, elapsed_ms=resp.elapsed_ms)

        if resp.status in (429, 503):
            wait = resp.headers.get("Retry-After", "")
            if wait.isdigit():
                time.sleep(min(int(wait), 60))

        return resp
