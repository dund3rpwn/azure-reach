#!/usr/bin/env python3
"""Read-only enforcement. A request is built only after it matches the allowlist."""

import re

DENIED_METHODS = frozenset({"PUT", "PATCH", "DELETE", "MERGE", "COPY"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Azure models a fair amount of reads as POST, so POST is allowed by exception
# only. The test is mutation, not sensitivity: listKeys returns existing keys
# and is fine, regenerateKey replaces them and is not.
POST_READS = (
    (r"^login\.microsoftonline\.com$", r"^/[^/]+/oauth2/v2\.0/token$"),
    (r"^management\.azure\.com$", r"^/providers/Microsoft\.ResourceGraph/resources$"),
    (r"^management\.azure\.com$", r"/providers/Microsoft\.Authorization/checkAccess$"),
    (r"^management\.azure\.com$", r"/listKeys$"),
    (r"^management\.azure\.com$", r"/listAccountSas$"),
    (r"^management\.azure\.com$", r"/listConnectionStrings$"),
    (r"^management\.azure\.com$", r"/publishxml/action$"),
    (r"^graph\.microsoft\.com$", r"/getMemberObjects$"),
)

# Redundant with the allowlist above, deliberately. If someone later broadens a
# path regex too far this still stops it.
DENIED_ACTIONS = re.compile(
    r"/(runCommand|regenerateKey|regenerateAccessKey|restart|redeploy|powerOff"
    r"|deallocate|delete|purge|write|invoke|start|stop|addKey|removeKey"
    r"|addPassword|removePassword)$",
    re.IGNORECASE,
)


class ReadOnlyViolation(Exception):
    """Raised before the request is built, so nothing was sent."""


def check(method, host, path):
    m = (method or "").upper()

    if DENIED_ACTIONS.search(path):
        raise ReadOnlyViolation("%s %s%s is a mutating action" % (m, host, path))
    if m in DENIED_METHODS:
        raise ReadOnlyViolation("%s is a write verb (%s%s)" % (m, host, path))
    if m in SAFE_METHODS:
        return
    if m == "POST":
        for host_re, path_re in POST_READS:
            if re.search(host_re, host) and re.search(path_re, path):
                return
        raise ReadOnlyViolation("POST %s%s is not in the read allowlist" % (host, path))

    raise ReadOnlyViolation("unknown method %r for %s%s" % (method, host, path))
