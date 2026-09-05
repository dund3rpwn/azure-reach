#!/usr/bin/env python3
"""JSONL log of every request sent. Never contains plaintext secrets."""

import hashlib
import json
import os
import time


def fingerprint(secret):
    """Stable non-reversible handle, so the same secret correlates across runs."""
    if secret is None:
        return None
    if isinstance(secret, str):
        secret = secret.encode("utf-8", "replace")
    return hashlib.sha256(secret).hexdigest()[:16]


class AuditLog:
    def __init__(self, path, user_agent, argv=None, cred_fp=None):
        self.path = path
        self.user_agent = user_agent
        self.run_id = hashlib.sha256(("%.6f" % time.time()).encode()).hexdigest()[:12]
        self.request_count = 0
        self.token_count = 0

        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        # Line buffered: a hard kill mid-run still leaves a truthful record.
        self._fh = open(path, "a", buffering=1, encoding="utf-8", newline="\n")
        # cred_fp says which credential the run used without storing it, which is
        # what lets two logs be compared months later.
        self.write(event="run_start", user_agent=user_agent, argv=argv, cred_fp=cred_fp)

    def write(self, **fields):
        row = dict(fields, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   run_id=self.run_id)
        self._fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        return row

    def request(self, method, url, status, *, pair_id=None, control=False, note=None,
                elapsed_ms=None):
        self.request_count += 1
        if "/oauth2/" in url:
            self.token_count += 1
        # pair_id links a control to the probe it guards, so the ladder can be
        # re-derived from the log alone.
        return self.write(event="request", method=method, url=url, status=status,
                          pair_id=pair_id, control=control, note=note,
                          elapsed_ms=elapsed_ms)

    def refused(self, method, url, reason):
        return self.write(event="refused", method=method, url=url, reason=reason)

    def close(self, status="ok"):
        self.write(event="run_end", status=status, requests_sent=self.request_count,
                   token_requests=self.token_count)
        self._fh.close()
