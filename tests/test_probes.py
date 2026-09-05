#!/usr/bin/env python3
"""Verdict logic, with canned responses. HTTP mechanics live in test_client.py."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import probes                                        # noqa: E402
from src.report import (ASSUMED, INCONCLUSIVE, VERIFIED,      # noqa: E402
                        VERIFIED_NEGATIVE)


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status = status
        self.body = json.dumps(payload).encode() if payload is not None else b""

    def json(self):
        return json.loads(self.body) if self.body else None


class FakeClient:
    """Matches queued responses by substring of the URL, in order."""

    def __init__(self, routes):
        self.routes = list(routes)
        self.sent = []

    def request(self, method, url, headers=None, body=None, pair_id=None,
                control=False, note=None, anonymous=False):
        self.sent.append({"method": method, "url": url, "body": body,
                          "anonymous": anonymous})
        for i, (fragment, resp) in enumerate(self.routes):
            if fragment in url:
                self.routes.pop(i)
                return resp
        raise AssertionError("unexpected request: %s %s" % (method, url))


class FakeTokens:
    def headers(self, audience):
        return {"Authorization": "Bearer fake"}


class FakeGate:
    def __init__(self):
        self.allowed = set()

    def allow_host(self, host):
        self.allowed.add(host)


CTX = {"app_id": "11111111-1111-1111-1111-111111111111",
       "object_id": "22222222-2222-2222-2222-222222222222",
       "tenant": "33333333-3333-3333-3333-333333333333"}


def verdict_for(findings, needle):
    for f in findings:
        if needle in f.capability:
            return f.verdict
    raise AssertionError("no finding matching %r in %s"
                         % (needle, [f.capability for f in findings]))


class SelfReadTrap(unittest.TestCase):
    """The headline case: a 200 on your own object proves nothing."""

    def test_self_read_ok_but_listing_denied(self):
        client = FakeClient([
            ("servicePrincipals?$top=1", FakeResponse(403)),
            ("servicePrincipals(appId=", FakeResponse(200, {"id": "self"})),
        ])
        out = probes.directory_read(client, FakeTokens(), CTX)
        self.assertEqual(verdict_for(out, "read directory objects"), VERIFIED_NEGATIVE)
        self.assertEqual(verdict_for(out, "read own service principal"), ASSUMED)

    def test_self_read_never_reported_as_verified(self):
        # Even when directory read genuinely works, the self-read stays ASSUMED:
        # no control can distinguish it from the free response.
        client = FakeClient([
            ("servicePrincipals?$top=1", FakeResponse(200, {"value": [{"id": "a"}]})),
            ("servicePrincipals(appId=", FakeResponse(200, {"id": "self"})),
        ])
        out = probes.directory_read(client, FakeTokens(), CTX)
        self.assertEqual(verdict_for(out, "read directory objects"), VERIFIED)
        self.assertEqual(verdict_for(out, "read own service principal"), ASSUMED)

    def test_self_read_denied_is_a_real_negative(self):
        client = FakeClient([
            ("servicePrincipals?$top=1", FakeResponse(403)),
            ("servicePrincipals(appId=", FakeResponse(403)),
        ])
        out = probes.directory_read(client, FakeTokens(), CTX)
        self.assertEqual(verdict_for(out, "read own service principal"), VERIFIED_NEGATIVE)


class EmptyListTrap(unittest.TestCase):
    """A principal with no roles gets 200 and an empty array, not a 403."""

    def test_empty_subscription_list_is_not_access(self):
        client = FakeClient([("/subscriptions", FakeResponse(200, {"value": []}))])
        findings, ids = probes.subscriptions(client, FakeTokens(), CTX)
        self.assertEqual(findings[0].verdict, VERIFIED_NEGATIVE)
        self.assertEqual(ids, [])

    def test_populated_subscription_list_is_access(self):
        client = FakeClient([("/subscriptions", FakeResponse(200, {"value": [
            {"subscriptionId": "sub-a", "displayName": "Prod"}]}))])
        findings, ids = probes.subscriptions(client, FakeTokens(), CTX)
        self.assertEqual(findings[0].verdict, VERIFIED)
        self.assertEqual(ids, ["sub-a"])

    def test_forbidden_is_a_negative(self):
        client = FakeClient([("/subscriptions", FakeResponse(403))])
        findings, ids = probes.subscriptions(client, FakeTokens(), CTX)
        self.assertEqual(findings[0].verdict, VERIFIED_NEGATIVE)


class RoleAssignments(unittest.TestCase):
    def test_denied_read_is_inconclusive_not_negative(self):
        # Microsoft.Authorization/*/read is separate from the access it describes,
        # so a principal can hold roles it cannot enumerate.
        client = FakeClient([("roleAssignments", FakeResponse(403))])
        out = probes.role_assignments(client, FakeTokens(), CTX, "sub-a")
        self.assertEqual(out[0].verdict, INCONCLUSIVE)

    def test_empty_assignments_is_negative(self):
        client = FakeClient([("roleAssignments", FakeResponse(200, {"value": []}))])
        out = probes.role_assignments(client, FakeTokens(), CTX, "sub-a")
        self.assertEqual(out[0].verdict, VERIFIED_NEGATIVE)

    def test_held_assignments_are_verified(self):
        client = FakeClient([("roleAssignments", FakeResponse(200, {"value": [
            {"properties": {"scope": "/subscriptions/sub-a"}}]}))])
        out = probes.role_assignments(client, FakeTokens(), CTX, "sub-a")
        self.assertEqual(out[0].verdict, VERIFIED)


class ResourceGraphPaging(unittest.TestCase):
    def test_order_by_is_forced(self):
        # $skip paging is only consistent against a totally ordered result set.
        client = FakeClient([("ResourceGraph", FakeResponse(200, {"data": []}))])
        probes._arg_query(client, FakeTokens(), ["sub-a"], "resources | project name")
        self.assertIn("order by", client.sent[0]["body"]["query"].lower())

    def test_existing_order_by_is_left_alone(self):
        client = FakeClient([("ResourceGraph", FakeResponse(200, {"data": []}))])
        probes._arg_query(client, FakeTokens(), ["sub-a"],
                          "resources | order by type asc")
        self.assertEqual(client.sent[0]["body"]["query"].lower().count("order by"), 1)

    def test_pages_accumulate_until_short_batch(self):
        full = [{"name": "r%d" % i, "type": "t"} for i in range(1000)]
        client = FakeClient([
            ("ResourceGraph", FakeResponse(200, {"data": full})),
            ("ResourceGraph", FakeResponse(200, {"data": full[:5]})),
        ])
        rows = probes._arg_query(client, FakeTokens(), ["sub-a"], "resources")
        self.assertEqual(len(rows), 1005)
        self.assertEqual(client.sent[0]["body"]["options"]["$skip"], 0)
        self.assertEqual(client.sent[1]["body"]["options"]["$skip"], 1000)

    def test_failure_returns_none(self):
        client = FakeClient([("ResourceGraph", FakeResponse(403))])
        self.assertIsNone(probes._arg_query(client, FakeTokens(), ["sub-a"], "resources"))


class Orchestration(unittest.TestCase):
    def test_only_named_subscriptions_are_touched(self):
        # Visible but unauthorized subscriptions must not be probed.
        client = FakeClient([
            ("servicePrincipals?$top=1", FakeResponse(403)),
            ("servicePrincipals(appId=", FakeResponse(200, {"id": "self"})),
            ("appRoleAssignments", FakeResponse(200, {"value": []})),
            ("/subscriptions?", FakeResponse(200, {"value": [
                {"subscriptionId": "authorized", "displayName": "A"},
                {"subscriptionId": "not-authorized", "displayName": "B"}]})),
            ("roleAssignments", FakeResponse(200, {"value": []})),
            ("Microsoft.KeyVault/vaults", FakeResponse(200, {"value": []})),
            ("storageAccounts?", FakeResponse(200, {"value": []})),
            ("ResourceGraph", FakeResponse(200, {"data": []})),
        ])
        probes.run_all(client, FakeTokens(), CTX, FakeGate(),
                       authorized_subscriptions=["authorized"])
        urls = " ".join(s["url"] for s in client.sent)
        self.assertIn("authorized", urls)
        self.assertNotIn("not-authorized", urls)
        arg = [s for s in client.sent if "ResourceGraph" in s["url"]][0]
        self.assertEqual(arg["body"]["subscriptions"], ["authorized"])



class KeyVaultDualModel(unittest.TestCase):
    """A vault authorizes by RBAC or by access policy, never both. Checking one
    and not the other is a false negative."""

    def vault(self, name, rbac, policy_oid=None):
        return {"name": name, "properties": {
            "vaultUri": "https://%s.vault.azure.net/" % name,
            "enableRbacAuthorization": rbac,
            "accessPolicies": [{"objectId": policy_oid}] if policy_oid else []}}

    def test_access_policy_vault_reachable(self):
        client = FakeClient([
            ("Microsoft.KeyVault/vaults", FakeResponse(200, {"value": [
                self.vault("polvault", rbac=False, policy_oid=CTX["object_id"])]})),
            ("polvault.vault.azure.net", FakeResponse(200, {"value": [
                {"id": "https://polvault.vault.azure.net/secrets/api-password"}]})),
        ])
        out = probes.key_vaults(client, FakeTokens(), CTX, "sub-a", FakeGate())
        self.assertEqual(verdict_for(out, "list secrets in polvault"), VERIFIED)

    def test_rbac_vault_reachable(self):
        client = FakeClient([
            ("Microsoft.KeyVault/vaults", FakeResponse(200, {"value": [
                self.vault("rbacvault", rbac=True)]})),
            ("rbacvault.vault.azure.net", FakeResponse(200, {"value": []})),
        ])
        out = probes.key_vaults(client, FakeTokens(), CTX, "sub-a", FakeGate())
        self.assertEqual(verdict_for(out, "list secrets in rbacvault"), VERIFIED)

    def test_vestigial_access_policy_is_called_out(self):
        # Principal is in the policy list, but the vault runs RBAC, so the policy
        # grants nothing. Worth saying rather than reporting a bare 403.
        client = FakeClient([
            ("Microsoft.KeyVault/vaults", FakeResponse(200, {"value": [
                self.vault("mixed", rbac=True, policy_oid=CTX["object_id"])]})),
            ("mixed.vault.azure.net", FakeResponse(403)),
        ])
        out = probes.key_vaults(client, FakeTokens(), CTX, "sub-a", FakeGate())
        finding = [f for f in out if "list secrets in mixed" in f.capability][0]
        self.assertEqual(finding.verdict, VERIFIED_NEGATIVE)
        self.assertIn("RBAC mode", finding.control)

    def test_secret_values_are_never_fetched(self):
        client = FakeClient([
            ("Microsoft.KeyVault/vaults", FakeResponse(200, {"value": [
                self.vault("v", rbac=True)]})),
            ("v.vault.azure.net", FakeResponse(200, {"value": [
                {"id": "https://v.vault.azure.net/secrets/db-password"}]})),
        ])
        probes.key_vaults(client, FakeTokens(), CTX, "sub-a", FakeGate())
        # Listing is /secrets; fetching a value would be /secrets/<name>.
        for sent in client.sent:
            self.assertNotIn("/secrets/db-password", sent["url"])

    def test_vault_host_registered_only_after_discovery(self):
        gate = FakeGate()
        client = FakeClient([
            ("Microsoft.KeyVault/vaults", FakeResponse(200, {"value": [
                self.vault("late", rbac=True)]})),
            ("late.vault.azure.net", FakeResponse(200, {"value": []})),
        ])
        probes.key_vaults(client, FakeTokens(), CTX, "sub-a", gate)
        self.assertIn("late.vault.azure.net", gate.allowed)


class StorageAnonymousControl(unittest.TestCase):
    """publicAccess is a claim. An unauthenticated fetch is the proof."""

    def account(self, name, allow_public=True):
        return {"name": name,
                "id": "/subscriptions/sub-a/resourceGroups/rg/providers/"
                      "Microsoft.Storage/storageAccounts/" + name,
                "properties": {"allowBlobPublicAccess": allow_public}}

    def containers(self, *specs):
        return {"value": [{"name": n, "properties": {"publicAccess": a}} for n, a in specs]}

    def test_claim_confirmed(self):
        client = FakeClient([
            ("storageAccounts?", FakeResponse(200, {"value": [self.account("acct")]})),
            ("blobServices/default/containers", FakeResponse(
                200, self.containers(("public-assets", "Blob")))),
            ("acct.blob.core.windows.net", FakeResponse(200)),
        ])
        out = probes.storage_accounts(client, FakeTokens(), CTX, "sub-a", FakeGate())
        self.assertEqual(verdict_for(out, "anonymous read"), VERIFIED)

    def test_claim_contradicted_by_reality(self):
        # The flag says public, the internet says no. Never assume reachability.
        client = FakeClient([
            ("storageAccounts?", FakeResponse(200, {"value": [self.account("acct")]})),
            ("blobServices/default/containers", FakeResponse(
                200, self.containers(("public-assets", "Blob")))),
            ("acct.blob.core.windows.net", FakeResponse(403)),
        ])
        out = probes.storage_accounts(client, FakeTokens(), CTX, "sub-a", FakeGate())
        finding = [f for f in out if "anonymous read" in f.capability][0]
        self.assertEqual(finding.verdict, VERIFIED_NEGATIVE)
        self.assertIn("overrides it", finding.control)

    def test_private_containers_are_not_probed_anonymously(self):
        client = FakeClient([
            ("storageAccounts?", FakeResponse(200, {"value": [self.account("acct")]})),
            ("blobServices/default/containers", FakeResponse(
                200, self.containers(("private-backups", "None")))),
        ])
        out = probes.storage_accounts(client, FakeTokens(), CTX, "sub-a", FakeGate())
        self.assertFalse([f for f in out if "anonymous read" in f.capability])
        self.assertFalse([s for s in client.sent if "blob.core.windows.net" in s["url"]])

    def test_anonymous_flag_is_set_on_the_control(self):
        client = FakeClient([
            ("storageAccounts?", FakeResponse(200, {"value": [self.account("acct")]})),
            ("blobServices/default/containers", FakeResponse(
                200, self.containers(("open", "Container")))),
            ("acct.blob.core.windows.net", FakeResponse(200)),
        ])
        probes.storage_accounts(client, FakeTokens(), CTX, "sub-a", FakeGate())
        anon = [s for s in client.sent if "blob.core.windows.net" in s["url"]][0]
        self.assertTrue(anon["anonymous"])


if __name__ == "__main__":
    unittest.main()
