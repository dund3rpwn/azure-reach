#!/usr/bin/env python3
"""Escalation edge rules and the matching engine."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import edges                                        # noqa: E402

VALID_KINDS = {"arm_role", "app_role", "data_access"}


def reach(arm=(), app=(), types=(), data=()):
    r = edges.empty_reach()
    r["arm_roles"].update(arm)
    r["app_roles"].update(app)
    r["resource_types"].update(types)
    r["data_access"].update(data)
    return r


def ids(found):
    return {e.rule.id for e in found}


class RulesFile(unittest.TestCase):
    """The rules are data, so the data gets checked."""

    def setUp(self):
        self.rules = edges.load()

    def test_rules_load(self):
        self.assertGreater(len(self.rules), 10)

    def test_ids_are_unique(self):
        seen = [r.id for r in self.rules]
        self.assertEqual(len(seen), len(set(seen)))

    def test_every_trigger_kind_is_known(self):
        for rule in self.rules:
            self.assertIn(rule.kind, VALID_KINDS, "bad kind on rule %s" % rule.id)

    def test_no_rule_is_missing_its_prose(self):
        # A rule that cannot explain itself is worse than no rule.
        for rule in self.rules:
            self.assertTrue(rule.reaches.strip(), "%s has no reaches" % rule.id)
            self.assertTrue(rule.precondition.strip(), "%s has no precondition" % rule.id)
            self.assertTrue(rule.trigger.strip(), "%s has no trigger" % rule.id)

    def test_resource_types_are_lowercase(self):
        # Resource Graph returns lowercase types and matching is done on that.
        for rule in self.rules:
            self.assertEqual(rule.needs, rule.needs.lower())


class Matching(unittest.TestCase):
    def test_contributor_alone_fires_no_resource_gated_edge(self):
        found = edges.evaluate(reach(arm=["Contributor"]))
        for edge in found:
            self.assertFalse(edge.rule.needs,
                             "%s fired without its resource present" % edge.rule.id)

    def test_contributor_plus_vm_reaches_the_identity(self):
        found = edges.evaluate(reach(arm=["Contributor"],
                                     types=["microsoft.compute/virtualmachines"]))
        self.assertIn("contributor-vm-identity", ids(found))

    def test_contributor_without_vm_does_not(self):
        found = edges.evaluate(reach(arm=["Contributor"],
                                     types=["microsoft.storage/storageaccounts"]))
        self.assertNotIn("contributor-vm-identity", ids(found))
        self.assertIn("contributor-storage-keys", ids(found))

    def test_owner_needs_no_resource(self):
        self.assertIn("owner-self-grant", ids(edges.evaluate(reach(arm=["Owner"]))))

    def test_application_readwrite_all_fires(self):
        found = edges.evaluate(reach(app=["Application.ReadWrite.All"]))
        self.assertIn("application-readwrite-all", ids(found))

    def test_keyvault_access_queues_recursion(self):
        found = edges.evaluate(reach(data=["keyvault_secrets"]))
        self.assertIn("keyvault-secret-recursion", ids(found))

    def test_storage_key_input_is_its_own_trigger(self):
        found = edges.evaluate(reach(data=["storage_keys"]))
        self.assertIn("storage-account-key", ids(found))

    def test_resource_type_match_is_case_insensitive(self):
        found = edges.evaluate(reach(arm=["Contributor"],
                                     types=["Microsoft.Compute/virtualMachines"]))
        self.assertIn("contributor-vm-identity", ids(found))

    def test_kinds_do_not_cross_match(self):
        # An ARM role name appearing in the app_role set must not fire an arm rule.
        self.assertEqual(edges.evaluate(reach(app=["Owner"])), [])

    def test_nothing_held_fires_nothing(self):
        self.assertEqual(edges.evaluate(edges.empty_reach()), [])


class RoleNames(unittest.TestCase):
    def test_builtin_guid_resolves(self):
        self.assertEqual(
            edges.role_name("/subscriptions/x/providers/Microsoft.Authorization/"
                            "roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"),
            "Contributor")

    def test_unknown_guid_passes_through(self):
        # Custom roles can carry roleAssignments/write just as Owner does, so an
        # unnamed role is a gap to notice rather than something to drop.
        out = edges.role_name("/x/11111111-2222-3333-4444-555555555555")
        self.assertEqual(out, "11111111-2222-3333-4444-555555555555")

    def test_none_stays_none(self):
        self.assertIsNone(edges.role_name(None))


if __name__ == "__main__":
    unittest.main()
