#!/usr/bin/env python3
"""Stage 0: work out what a credential claims, offline.

Nothing here touches the network, so it costs no sign-in event and shows up in
nobody's logs. For a JWT or a SAS token it usually answers most of the question
on its own, which is why it runs before anything authenticates.
"""

import base64
import binascii
import calendar
import json
import re
import time
from urllib.parse import parse_qs

SAS_PERMS = {
    "r": "read", "w": "write", "d": "delete", "l": "list", "a": "add",
    "c": "create", "u": "update", "p": "process", "t": "tag", "f": "filter",
    "i": "set-immutability", "y": "permanent-delete", "x": "delete-version",
    "m": "move", "e": "execute",
}

SAS_SERVICES = {"b": "blob", "q": "queue", "t": "table", "f": "file"}
SAS_RESOURCE_TYPES = {"s": "service", "c": "container", "o": "object"}


def _b64url(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _expiry(epoch):
    if epoch is None:
        return None, None
    left = int(epoch) - int(time.time())
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch)))
    return stamp, left


def jwt(token):
    """Decode a bearer token. Signature is not checked -- we are reading claims,
    not trusting them; the issuer will do the trusting."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    try:
        claims = json.loads(_b64url(parts[1]))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("undecodable JWT payload: %s" % exc)

    expires_at, seconds_left = _expiry(claims.get("exp"))
    roles = claims.get("roles") or []
    scopes = (claims.get("scp") or "").split() if claims.get("scp") else []

    return {
        "kind": "jwt",
        "audience": claims.get("aud"),
        "tenant": claims.get("tid"),
        "object_id": claims.get("oid"),
        "app_id": claims.get("appid") or claims.get("azp"),
        "app_name": claims.get("app_displayname"),
        "issuer": claims.get("iss"),
        # roles are application permissions (no user present), scp are delegated
        # scopes (acting for a signed-in user). Which one is populated decides
        # whether IDOR-style ownership checks are even possible later.
        "app_roles": roles,
        "delegated_scopes": scopes,
        "identity_type": claims.get("idtyp"),
        "expires_at": expires_at,
        "seconds_left": seconds_left,
        "declared": roles + scopes,
    }


def sas(token):
    """Parse a SAS token or a URL containing one."""
    query = token.split("?", 1)[1] if "?" in token else token
    q = {k: v[0] for k, v in parse_qs(query).items()}
    if "sig" not in q:
        raise ValueError("no sig parameter, not a SAS token")

    perms = [SAS_PERMS.get(c, c) for c in q.get("sp", "")]
    expires_at, seconds_left = _expiry(
        calendar.timegm(time.strptime(q["se"], "%Y-%m-%dT%H:%M:%SZ")) if "se" in q else None)

    return {
        "kind": "sas",
        "permissions": perms,
        "services": [SAS_SERVICES.get(c, c) for c in q.get("ss", "")],
        "resource_types": [SAS_RESOURCE_TYPES.get(c, c) for c in q.get("srt", "")],
        "resource": q.get("sr"),
        "signed_version": q.get("sv"),
        "protocol": q.get("spr"),
        "ip_restriction": q.get("sip"),
        # skoid means it was signed with a user delegation key rather than the
        # account key, so it dies with that key and carries the signer identity.
        "user_delegation": "skoid" in q,
        "delegated_object_id": q.get("skoid"),
        "expires_at": expires_at,
        "seconds_left": seconds_left,
        "declared": perms,
    }


def connection_string(value):
    """Parse a Key=Value;Key=Value connection string."""
    pairs = {}
    for part in value.strip().rstrip(";").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            pairs[k.strip().lower()] = v.strip()
    if not pairs:
        raise ValueError("not a connection string")

    out = {"kind": "connection_string", "service": None, "endpoint": None,
           "account": None, "key_name": None, "declared": []}

    if "accountname" in pairs and "accountkey" in pairs:
        out.update(service="storage", account=pairs["accountname"],
                   endpoint="https://%s.blob.%s" % (
                       pairs["accountname"], pairs.get("endpointsuffix", "core.windows.net")),
                   # An account key is unscoped and unexpiring: full control of
                   # every service in the account until someone rotates it.
                   declared=["storage-account-key: full control of all services"])
    elif "sharedaccesskeyname" in pairs:
        endpoint = pairs.get("endpoint", "")
        out.update(service="servicebus/eventhub", endpoint=endpoint,
                   key_name=pairs["sharedaccesskeyname"],
                   declared=["sas-policy: %s" % pairs["sharedaccesskeyname"]])
    elif "accountendpoint" in pairs and "accountkey" in pairs:
        out.update(service="cosmos", endpoint=pairs["accountendpoint"],
                   declared=["cosmos-primary-key: full control"])
    elif "endpoint" in pairs and "id" in pairs and "secret" in pairs:
        out.update(service="appconfiguration", endpoint=pairs["endpoint"],
                   key_name=pairs["id"], declared=["appconfig-access-key"])
    else:
        out["service"] = "unknown"

    return out


def detect(blob):
    """Work out what a blob of credential material is, and parse it."""
    blob = blob.strip()
    if re.match(r"^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", blob):
        return jwt(blob)
    if "sig=" in blob and ("sp=" in blob or "sr=" in blob or "ss=" in blob):
        return sas(blob)
    if "=" in blob and ";" in blob:
        return connection_string(blob)
    raise ValueError("unrecognised credential format")
