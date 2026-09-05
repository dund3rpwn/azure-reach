#!/usr/bin/env python3
"""Token acquisition, cached per audience.

Caching is not a performance tweak. Every client_credentials call lands in Entra
service principal sign-in logs with the credential id and the User-Agent, and
those entries cannot be altered or deleted -- while the control-plane reads that
follow are not written to the Activity Log at all. Authenticating is the loud
part, so we do it once per audience and reuse.
"""

import time
from urllib.parse import urlencode

ARM = "https://management.azure.com"
GRAPH = "https://graph.microsoft.com"
VAULT = "https://vault.azure.net"
STORAGE = "https://storage.azure.com"


class TokenError(Exception):
    pass


class TokenSource:
    def __init__(self, client, tenant, client_id, client_secret):
        self.client = client
        self.tenant = tenant
        self.client_id = client_id
        self.client_secret = client_secret
        self._cache = {}

    def get(self, audience):
        cached = self._cache.get(audience)
        # 60s of slack so a token cannot expire between the check and the call.
        if cached and cached["expires_at"] - 60 > time.time():
            return cached["token"]

        body = urlencode({
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": audience + "/.default",
        })
        resp = self.client.request(
            "POST", "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % self.tenant,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body, note="token for %s" % audience)

        payload = resp.json() or {}
        if resp.status != 200 or "access_token" not in payload:
            raise TokenError("%s: %s" % (
                payload.get("error", resp.status),
                payload.get("error_description", "")[:200] or resp.body[:200]))

        self._cache[audience] = {
            "token": payload["access_token"],
            "expires_at": time.time() + int(payload.get("expires_in", 3600)),
        }
        return payload["access_token"]

    def headers(self, audience):
        return {"Authorization": "Bearer " + self.get(audience)}
