#!/usr/bin/env python3
"""Stage 1 and 2: what the credential actually reaches, with paired controls.

Two response shapes look like access and are not. Both are handled here rather
than in the renderer, because the point is the verdict, not the wording.
"""

from urllib.parse import quote

from . import edges, tokens
from .report import (ASSUMED, INCONCLUSIVE, VERIFIED, VERIFIED_NEGATIVE, Finding)

ARM_API = "2022-12-01"
ROLE_API = "2022-04-01"
ARG_API = "2021-03-01"


def _graph(client, tok, path, note=None, pair_id=None, control=False):
    return client.request("GET", "https://graph.microsoft.com/v1.0" + path,
                          headers=tok.headers(tokens.GRAPH), note=note,
                          pair_id=pair_id, control=control)


def _arm(client, tok, path, note=None, pair_id=None, control=False):
    return client.request("GET", "https://management.azure.com" + path,
                          headers=tok.headers(tokens.ARM), note=note,
                          pair_id=pair_id, control=control)


def directory_read(client, tok, ctx):
    """Can this principal read the directory, or only itself?

    A service principal can read its own object with nothing granted at all, so
    a 200 there says nothing about directory access. The self-read is therefore
    not a probe in its own right -- it is the control for this one. If reading
    ourselves works and listing anyone else does not, the 200 is proven to be
    the zero-permission artifact rather than evidence of access.
    """
    app_id = ctx.get("app_id")
    findings = []

    probe = _graph(client, tok, "/servicePrincipals?$top=1&$select=id",
                   note="list servicePrincipals", pair_id="dirread")

    control = None
    if app_id:
        control = _graph(client, tok,
                         "/servicePrincipals(appId='%s')" % quote(app_id, safe=""),
                         note="self-read control", pair_id="dirread", control=True)

    if probe.status == 200:
        count = len((probe.json() or {}).get("value", []))
        findings.append(Finding(
            "graph: read directory objects", VERIFIED,
            evidence="listed servicePrincipals (%d returned)" % count,
            control="self-read returned %s" % (control.status if control else "not run")))
    elif probe.status in (401, 403):
        findings.append(Finding(
            "graph: read directory objects", VERIFIED_NEGATIVE,
            evidence="HTTP %d listing servicePrincipals" % probe.status))
    else:
        findings.append(Finding(
            "graph: read directory objects", INCONCLUSIVE,
            evidence="HTTP %s listing servicePrincipals" % probe.status))

    if control is not None:
        if control.status == 200 and probe.status != 200:
            findings.append(Finding(
                "graph: read own service principal", ASSUMED,
                evidence="HTTP 200 on own object while listing others returned %d"
                         % probe.status,
                control="none possible -- Entra permits this read with zero permissions"))
        elif control.status == 200:
            findings.append(Finding(
                "graph: read own service principal", ASSUMED,
                evidence="HTTP 200 on own object",
                control="none possible -- Entra permits this read with zero permissions"))
        else:
            findings.append(Finding(
                "graph: read own service principal", VERIFIED_NEGATIVE,
                evidence="HTTP %d on own object" % control.status))

    return findings


def app_role_assignments(client, tok, ctx):
    """Application permissions actually granted on the principal."""
    oid = ctx.get("object_id")
    if not oid:
        return [Finding("graph: app role assignments", INCONCLUSIVE,
                        evidence="object id unknown, cannot query")]

    resp = _graph(client, tok, "/servicePrincipals/%s/appRoleAssignments" % quote(oid, safe=""),
                  note="own app role assignments")
    if resp.status != 200:
        return [Finding("graph: app role assignments", INCONCLUSIVE,
                        evidence="HTTP %s" % resp.status)]

    grants = (resp.json() or {}).get("value", [])
    if not grants:
        return [Finding("graph: app role assignments", VERIFIED_NEGATIVE,
                        evidence="no application permissions granted")]
    names = ", ".join(sorted({g.get("resourceDisplayName", "?") for g in grants}))
    return [Finding("graph: app role assignments", VERIFIED,
                    evidence="%d grant(s) against %s" % (len(grants), names))]


def subscriptions(client, tok, ctx):
    """Which subscriptions this principal can see.

    A principal with no role assignments does not get a 403 here -- it gets
    200 with an empty value array. That is a successful HTTP response meaning
    no access at all, and reading it as access is the second false positive
    this tool exists to avoid.
    """
    resp = _arm(client, tok, "/subscriptions?api-version=" + ARM_API,
                note="list subscriptions")

    if resp.status != 200:
        return [Finding("arm: enumerate subscriptions",
                        VERIFIED_NEGATIVE if resp.status in (401, 403) else INCONCLUSIVE,
                        evidence="HTTP %s" % resp.status)], []

    found = (resp.json() or {}).get("value", [])
    if not found:
        return [Finding(
            "arm: enumerate subscriptions", VERIFIED_NEGATIVE,
            evidence="HTTP 200 with an empty list",
            control="200 here means the call succeeded and returned nothing; it is "
                    "not evidence of ARM access")], []

    ids = [s["subscriptionId"] for s in found if "subscriptionId" in s]
    names = ", ".join(s.get("displayName", "?") for s in found[:5])
    return [Finding("arm: enumerate subscriptions", VERIFIED,
                    evidence="%d subscription(s): %s" % (len(ids), names))], ids


def role_assignments(client, tok, ctx, subscription, reach=None):
    """Roles held by this principal in one subscription -- the real blast radius."""
    oid = ctx.get("object_id")
    if not oid:
        return [Finding("arm: own role assignments in %s" % subscription, INCONCLUSIVE,
                        evidence="object id unknown")]

    path = ("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments"
            "?api-version=%s&$filter=principalId+eq+'%s'" % (subscription, ROLE_API, oid))
    resp = _arm(client, tok, path, note="own role assignments")

    if resp.status in (401, 403):
        # Not the same as having no access. Microsoft.Authorization/*/read is a
        # separate permission from the data access it describes, so a principal
        # can hold roles it cannot enumerate.
        return [Finding("arm: own role assignments in %s" % subscription, INCONCLUSIVE,
                        evidence="HTTP %d reading roleAssignments" % resp.status,
                        control="cannot read assignments; this does not imply no access")]
    if resp.status != 200:
        return [Finding("arm: own role assignments in %s" % subscription, INCONCLUSIVE,
                        evidence="HTTP %s" % resp.status)]

    held = (resp.json() or {}).get("value", [])
    if not held:
        return [Finding("arm: own role assignments in %s" % subscription, VERIFIED_NEGATIVE,
                        evidence="no role assignments for this principal")]

    scopes = {r.get("properties", {}).get("scope", "?") for r in held}
    names = {edges.role_name(r.get("properties", {}).get("roleDefinitionId")) for r in held}
    names.discard(None)
    if reach is not None:
        reach["arm_roles"].update(names)
    return [Finding("arm: own role assignments in %s" % subscription, VERIFIED,
                    evidence="%s across %d scope(s)"
                             % (", ".join(sorted(names)) or "%d assignment(s)" % len(held),
                                len(scopes)))]


def resource_graph(client, tok, ctx, subscription_ids, reach=None):
    """Resources visible to this principal, via Resource Graph."""
    if not subscription_ids:
        return [Finding("arm: enumerate resources", INCONCLUSIVE,
                        evidence="no authorized subscriptions to query")]

    rows = _arg_query(client, tok, subscription_ids,
                      "resources | project name, type, resourceGroup, subscriptionId")
    if rows is None:
        return [Finding("arm: enumerate resources", INCONCLUSIVE,
                        evidence="Resource Graph query failed")]
    if not rows:
        return [Finding("arm: enumerate resources", VERIFIED_NEGATIVE,
                        evidence="Resource Graph returned no resources")]

    kinds = {}
    for row in rows:
        kinds[row.get("type", "?")] = kinds.get(row.get("type", "?"), 0) + 1
    if reach is not None:
        reach["resource_types"].update(k.lower() for k in kinds)
    top = ", ".join("%s (%d)" % (k, v) for k, v in
                    sorted(kinds.items(), key=lambda kv: -kv[1])[:5])
    return [Finding("arm: enumerate resources", VERIFIED,
                    evidence="%d resource(s) across %d type(s): %s"
                             % (len(rows), len(kinds), top))]


def _arg_query(client, tok, subscription_ids, query, page=1000, cap=20000):
    """Paged Resource Graph query.

    $skip paging is only consistent against a totally ordered result set. Without
    an explicit order by, rows move between pages and you get duplicates and
    silent omissions in the same run, which looks like flaky infrastructure and
    is actually the query.
    """
    if "order by" not in query.lower():
        query += " | order by name asc, type asc"

    out, skip = [], 0
    while skip < cap:
        resp = client.request(
            "POST", "https://management.azure.com/providers/Microsoft.ResourceGraph/"
                    "resources?api-version=" + ARG_API,
            headers=tok.headers(tokens.ARM),
            body={"subscriptions": subscription_ids, "query": query,
                  "options": {"$top": page, "$skip": skip}},
            note="resource graph skip=%d" % skip)

        if resp.status != 200:
            return out if out else None
        batch = (resp.json() or {}).get("data", [])
        if not batch:
            break
        out.extend(batch)
        if len(batch) < page:
            break
        skip += page
    return out


def run_all(client, tok, ctx, gate, authorized_subscriptions=None, reach=None):
    reach = edges.empty_reach() if reach is None else reach
    # Application permissions come from the token we already hold, so naming them
    # costs nothing beyond the sign-in we had to make anyway.
    reach["app_roles"].update(ctx.get("app_roles") or [])

    findings = []
    findings.extend(directory_read(client, tok, ctx))
    findings.extend(app_role_assignments(client, tok, ctx))

    sub_findings, visible = subscriptions(client, tok, ctx)
    findings.extend(sub_findings)

    # Only touch subscriptions the operator named, even if more are visible.
    targets = [s for s in visible if s in (authorized_subscriptions or [])]
    for sub in targets:
        findings.extend(role_assignments(client, tok, ctx, sub, reach))
        findings.extend(key_vaults(client, tok, ctx, sub, gate, reach))
        findings.extend(storage_accounts(client, tok, ctx, sub, gate))

    # Resource Graph runs last: the resource types it returns are what decide
    # which Contributor edges actually apply.
    findings.extend(resource_graph(client, tok, ctx, targets, reach))

    return findings, reach


KV_MGMT_API = "2023-07-01"
KV_DATA_API = "7.4"
STORAGE_API = "2023-05-01"


def key_vaults(client, tok, ctx, subscription, gate, reach=None):
    """Key Vault reach, checked against both authorization models.

    A vault authorizes through EITHER Azure RBAC OR the legacy access policy
    list, never both, and the two are configured in different places. Checking
    one model and reporting "no access" on the other is a false negative, so the
    data-plane probe here is model-agnostic -- it just asks the vault -- and the
    control-plane listing only says which model answered.

    Secret values are never read. The list operation returns identifiers and
    metadata but no values, and that is where this stops: proving you can list
    is the finding, pulling the contents is exfiltration nobody asked for.
    Reachable secrets are reported as recursion targets instead.
    """
    listing = _arm(client, tok,
                   "/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=%s"
                   % (subscription, KV_MGMT_API), note="list key vaults")

    if listing.status != 200:
        return [Finding("keyvault: enumerate vaults in %s" % subscription,
                        VERIFIED_NEGATIVE if listing.status in (401, 403) else INCONCLUSIVE,
                        evidence="HTTP %s" % listing.status)]

    vaults = (listing.json() or {}).get("value", [])
    if not vaults:
        return [Finding("keyvault: enumerate vaults in %s" % subscription, VERIFIED_NEGATIVE,
                        evidence="no vaults visible")]

    findings = [Finding("keyvault: enumerate vaults in %s" % subscription, VERIFIED,
                        evidence="%d vault(s) visible" % len(vaults))]
    for vault in vaults:
        finding = _vault_secrets(client, tok, ctx, vault, gate)
        if reach is not None and finding.verdict == VERIFIED:
            reach["data_access"].add("keyvault_secrets")
        findings.append(finding)
    return findings


def _vault_secrets(client, tok, ctx, vault, gate):
    name = vault.get("name")
    props = vault.get("properties", {})
    uri = props.get("vaultUri") or "https://%s.vault.azure.net/" % name
    rbac = bool(props.get("enableRbacAuthorization"))
    model = "RBAC" if rbac else "access policy"

    # Registered only now, having been found inside an authorized subscription.
    gate.allow_host(uri.split("//", 1)[-1].strip("/"))

    oid = (ctx.get("object_id") or "").lower()
    in_policy = any((p.get("objectId") or "").lower() == oid
                    for p in props.get("accessPolicies", []))

    probe = client.request(
        "GET", "%ssecrets?api-version=%s&maxresults=25"
               % (uri if uri.endswith("/") else uri + "/", KV_DATA_API),
        headers=tok.headers(tokens.VAULT), note="list secrets in %s" % name)

    capability = "keyvault: list secrets in %s" % name

    if probe.status == 200:
        secrets = (probe.json() or {}).get("value", [])
        names = [s.get("id", "").rsplit("/", 1)[-1] for s in secrets][:5]
        return Finding(
            capability, VERIFIED,
            evidence="%d secret(s) listed, values not read: %s"
                     % (len(secrets), ", ".join(n for n in names if n) or "-"),
            control="vault is in %s mode%s"
                    % (model, "; principal is in the access policy" if in_policy else ""))

    if probe.status in (401, 403):
        # An access policy entry the data plane ignores means RBAC is in force
        # and the policy is vestigial -- a real misconfiguration, worth saying.
        note = ("principal is in the access policy, but the vault is in RBAC mode, so the "
                "policy grants nothing" if in_policy and rbac else "vault is in %s mode" % model)
        return Finding(capability, VERIFIED_NEGATIVE,
                       evidence="HTTP %d" % probe.status, control=note)

    return Finding(capability, INCONCLUSIVE, evidence="HTTP %s" % probe.status)


def storage_accounts(client, tok, ctx, subscription, gate):
    """Storage reach, and whether the public-access flags are actually true.

    allowBlobPublicAccess and a container's publicAccess setting are claims about
    configuration. Whether an anonymous client can really read the container is a
    different question, and the only way to answer it is to ask without
    credentials -- so every container claiming anonymous access gets an
    unauthenticated fetch as a positive control.
    """
    listing = _arm(client, tok,
                   "/subscriptions/%s/providers/Microsoft.Storage/storageAccounts"
                   "?api-version=%s" % (subscription, STORAGE_API),
                   note="list storage accounts")

    if listing.status != 200:
        return [Finding("storage: enumerate accounts in %s" % subscription,
                        VERIFIED_NEGATIVE if listing.status in (401, 403) else INCONCLUSIVE,
                        evidence="HTTP %s" % listing.status)]

    accounts = (listing.json() or {}).get("value", [])
    if not accounts:
        return [Finding("storage: enumerate accounts in %s" % subscription, VERIFIED_NEGATIVE,
                        evidence="no storage accounts visible")]

    findings = [Finding("storage: enumerate accounts in %s" % subscription, VERIFIED,
                        evidence="%d account(s) visible" % len(accounts))]
    for account in accounts:
        findings.extend(_containers(client, tok, account, gate))
    return findings


def _containers(client, tok, account, gate):
    name = account.get("name")
    allows_public = account.get("properties", {}).get("allowBlobPublicAccess")
    blob_host = "%s.blob.core.windows.net" % name
    gate.allow_host(blob_host)

    resp = _arm(client, tok, "%s/blobServices/default/containers?api-version=%s"
                % (account.get("id", ""), STORAGE_API),
                note="list containers in %s" % name)

    if resp.status != 200:
        return [Finding("storage: list containers in %s" % name,
                        VERIFIED_NEGATIVE if resp.status in (401, 403) else INCONCLUSIVE,
                        evidence="HTTP %s" % resp.status)]

    containers = (resp.json() or {}).get("value", [])
    out = [Finding("storage: list containers in %s" % name, VERIFIED,
                   evidence="%d container(s); account allowBlobPublicAccess=%s"
                            % (len(containers), allows_public))]

    for container in containers:
        access = container.get("properties", {}).get("publicAccess")
        if access and access.lower() != "none":
            out.append(_anonymous_control(client, blob_host, container.get("name"), access))
    return out


def _anonymous_control(client, blob_host, container, claimed):
    """Fetch with no credential at all. The flag is a claim; this is the proof."""
    url = "https://%s/%s?restype=container&comp=list&maxresults=1" % (blob_host, container)
    capability = "storage: anonymous read of %s/%s" % (blob_host, container)

    resp = client.request("GET", url, anonymous=True, note="anonymous control", control=True)

    if resp.status == 200:
        return Finding(capability, VERIFIED,
                       evidence="HTTP 200 with no credential",
                       control="config claimed publicAccess=%s and it holds" % claimed)
    if resp.status in (401, 403, 404):
        return Finding(capability, VERIFIED_NEGATIVE,
                       evidence="HTTP %d with no credential" % resp.status,
                       control="config claimed publicAccess=%s, but anonymous access does not "
                               "work -- a network rule or the account-level flag overrides it"
                               % claimed)
    return Finding(capability, INCONCLUSIVE, evidence="HTTP %s" % resp.status)
