#!/usr/bin/env python3
"""Escalation edges: what this credential could reach next.

Every edge here is an inference drawn from what the probes proved, and none of
them are taken. Reporting "Contributor on a resource group containing a VM means
the VM managed identity is reachable" is useful; running the command that does it
is a decision for a human with a scope document in front of them.
"""

import csv
import os

RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "edges.tsv")

# Built-in role definition ids are the same GUIDs in every tenant, so a held role
# can be named without spending a request on roleDefinitions.
BUILTIN_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c": "Virtual Machine Contributor",
    "de139f84-1756-47ae-9be6-808fbbe84772": "Website Contributor",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
    "17d1049b-9a84-46fb-8f53-869881c3d3ab": "Storage Account Contributor",
}


def role_name(role_definition_id):
    """Name a role from its definition id, or hand back the id unchanged.

    An unrecognised id is almost always a custom role. Those can carry
    Microsoft.Authorization/roleAssignments/write just as Owner does, so an
    unnamed role is a gap in this analysis rather than a safe default.
    """
    if not role_definition_id:
        return None
    return BUILTIN_ROLES.get(role_definition_id.rsplit("/", 1)[-1].lower(),
                             role_definition_id.rsplit("/", 1)[-1])


class Rule:
    def __init__(self, row):
        self.id = row["id"]
        self.kind = row["trigger_kind"]
        self.trigger = row["trigger"]
        self.needs = (row.get("needs") or "").strip().lower()
        self.reaches = row["reaches"]
        self.precondition = row["precondition"]


class Edge:
    def __init__(self, rule, evidence):
        self.rule = rule
        self.evidence = evidence

    def as_dict(self):
        return {"id": self.rule.id, "trigger": self.rule.trigger,
                "reaches": self.rule.reaches, "precondition": self.rule.precondition,
                "evidence": self.evidence}


def load(path=None):
    with open(path or RULES_FILE, encoding="utf-8") as fh:
        rows = [line for line in fh if not line.startswith("#")]
    return [Rule(r) for r in csv.DictReader(rows, delimiter="\t") if r.get("id")]


def empty_reach():
    return {"arm_roles": set(), "app_roles": set(),
            "resource_types": set(), "data_access": set()}


def evaluate(reach, rules=None):
    """Match proven capability against the rule set."""
    held = {
        "arm_role": {r for r in reach.get("arm_roles", set()) if r},
        "app_role": {r for r in reach.get("app_roles", set()) if r},
        "data_access": {d for d in reach.get("data_access", set()) if d},
    }
    types = {t.lower() for t in reach.get("resource_types", set()) if t}

    out = []
    for rule in (rules if rules is not None else load()):
        if rule.trigger not in held.get(rule.kind, set()):
            continue
        if rule.needs and rule.needs not in types:
            continue

        evidence = "holds %s" % rule.trigger
        if rule.needs:
            evidence += ", and %s is visible in scope" % rule.needs
        out.append(Edge(rule, evidence))
    return out
