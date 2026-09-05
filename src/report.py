#!/usr/bin/env python3
"""Verdicts and output rendering."""

VERIFIED = "VERIFIED"                    # probe passed and its control behaved
VERIFIED_NEGATIVE = "VERIFIED NEGATIVE"  # explicit 403, permission proven absent
NOT_TESTED = "NOT TESTED"                # claimed by the token, never exercised
ASSUMED = "ASSUMED"                      # probe passed but no valid control exists
INCONCLUSIVE = "INCONCLUSIVE"            # 404, timeout, ambiguous

ORDER = [VERIFIED, ASSUMED, VERIFIED_NEGATIVE, INCONCLUSIVE, NOT_TESTED]


class Finding:
    def __init__(self, capability, verdict, evidence=None, control=None):
        self.capability = capability
        self.verdict = verdict
        self.evidence = evidence
        self.control = control

    def as_dict(self):
        return {"capability": self.capability, "verdict": self.verdict,
                "evidence": self.evidence, "control": self.control}


def render_introspection(parsed):
    lines = ["credential type : %s" % parsed["kind"]]
    for key in ("service", "audience", "tenant", "app_id", "app_name", "object_id",
                "account", "endpoint", "key_name", "resource", "identity_type",
                "signed_version", "protocol", "ip_restriction"):
        if parsed.get(key):
            lines.append("%-16s: %s" % (key.replace("_", " "), parsed[key]))

    for key in ("services", "resource_types", "permissions"):
        if parsed.get(key):
            lines.append("%-16s: %s" % (key.replace("_", " "), ", ".join(parsed[key])))

    if parsed.get("user_delegation"):
        lines.append("%-16s: yes (signed with a user delegation key)" % "delegated")

    left = parsed.get("seconds_left")
    if parsed.get("expires_at"):
        if left is None:
            state = "unknown"
        elif left <= 0:
            state = "EXPIRED"
        elif left < 3600:
            state = "%dm left" % (left // 60)
        else:
            state = "%dh left" % (left // 3600)
        lines.append("%-16s: %s (%s)" % ("expires", parsed["expires_at"], state))
    elif parsed["kind"] == "connection_string":
        lines.append("%-16s: never (rotation is the only revocation)" % "expires")

    declared = parsed.get("declared") or []
    lines.append("")
    if declared:
        lines.append("declared capability (%s):" % NOT_TESTED)
        for item in declared:
            lines.append("  - %s" % item)
    else:
        lines.append("declared capability: none stated in the credential itself")
    return "\n".join(lines)


def render_footprint(audit, network_used):
    if not network_used:
        return ("footprint: no requests sent. Nothing to correlate in sign-in logs, "
                "Activity Log or Graph activity logs.")
    lines = [
        "footprint:",
        "  %d token acquisition(s) -- always recorded in Entra service principal" % audit.token_count,
        "     sign-in logs, with the credential id and this User-Agent:",
        "     %s" % audit.user_agent,
        "  %d other request(s) -- control plane reads are not written to the" % (
            audit.request_count - audit.token_count),
        "     Activity Log by default.",
    ]
    return "\n".join(lines)


def render_findings(findings):
    if not findings:
        return "no checks ran"

    lines = []
    for verdict in ORDER:
        group = [f for f in findings if f.verdict == verdict]
        if not group:
            continue
        lines.append("")
        lines.append("%s (%d)" % (verdict, len(group)))
        lines.append("-" * len(lines[-1]))
        for f in group:
            lines.append("  %s" % f.capability)
            if f.evidence:
                lines.append("      evidence: %s" % f.evidence)
            if f.control:
                lines.append("      control : %s" % f.control)

    if any(f.verdict == ASSUMED for f in findings):
        lines.append("")
        lines.append("ASSUMED means the call succeeded but no control can distinguish real")
        lines.append("access from a response Azure gives away for free. Do not report it as")
        lines.append("access without a second, independent check.")
    return "\n".join(lines).lstrip("\n")


def render_edges(found):
    if not found:
        return ("escalation edges: none. Nothing proven above matches a known "
                "escalation path.")

    lines = ["escalation edges (inferred from what was proven, none taken)",
             "-" * 58]
    for edge in found:
        lines.append("  %s" % edge.rule.reaches)
        lines.append("      because : %s" % edge.evidence)
        lines.append("      caveat  : %s" % edge.rule.precondition)
        lines.append("      rule    : %s" % edge.rule.id)
        lines.append("")
    lines.append("These are paths, not results. Each one needs its own decision before")
    lines.append("anyone walks it, and none of them were walked here.")
    return "\n".join(lines)
