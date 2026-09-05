#!/usr/bin/env python3
"""Authorization gate. Sitting in a tenant is not permission to test it."""

import re
from urllib.parse import urlsplit

SUB_IN_PATH = re.compile(r"/subscriptions/([0-9a-fA-F-]{36})(?:/|$)")
TENANT_IN_PATH = re.compile(r"^/([0-9a-fA-F-]{36})/oauth2/")

# Control-plane hosts, where the subscription in the path is what gets checked.
CONTROL_PLANE = frozenset({
    "login.microsoftonline.com",
    "management.azure.com",
    "graph.microsoft.com",
})


class OutOfScope(Exception):
    """Raised before the request is built, so nothing was sent."""


class Gate:
    """Discovery is always allowed; touching a named subscription is not.

    Failing closed on an empty allowlist would be unusable -- you cannot name
    the subscriptions you are authorized for before you know any exist. So
    GET /subscriptions ("what exists") always passes, and /subscriptions/{id}/...
    ("what is inside") needs the id passed in. First run tells you what to go
    and get authorization for; second run names it.

    Data-plane hosts are the other half. A vault or storage endpoint carries no
    subscription in its URL, so path checking cannot see it and every data-plane
    request would pass unexamined. Instead those hosts have to be registered with
    allow_host() as they are discovered inside an authorized subscription, and
    anything unregistered is refused.
    """

    def __init__(self, subscriptions=None, tenants=None):
        self.subscriptions = {s.strip().lower() for s in (subscriptions or []) if s.strip()}
        self.tenants = {t.strip().lower() for t in (tenants or []) if t.strip()}
        self._data_plane = set()

    @property
    def discovery_only(self):
        return not self.subscriptions

    def allow_host(self, host):
        """Register a data-plane host found inside an authorized subscription."""
        if host:
            self._data_plane.add(host.lower())

    def check(self, url):
        parts = urlsplit(url)
        path = parts.path
        host = (parts.hostname or "").lower()

        tenant = TENANT_IN_PATH.match(path)
        if tenant and self.tenants and tenant.group(1).lower() not in self.tenants:
            raise OutOfScope("tenant %s is not in --tenants" % tenant.group(1))

        found = SUB_IN_PATH.search(path)
        if found:
            sub = found.group(1).lower()
            if self.discovery_only:
                raise OutOfScope(
                    "subscription %s not authorized: no --subscriptions given, so this run "
                    "is discovery-only" % sub)
            if sub not in self.subscriptions:
                raise OutOfScope("subscription %s is not in --subscriptions" % sub)
            return

        if host in CONTROL_PLANE:
            return

        if host not in self._data_plane:
            raise OutOfScope(
                "%s is not a registered data-plane host; it was not discovered inside an "
                "authorized subscription" % host)
