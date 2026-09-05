#!/usr/bin/env python3
"""azure-reach -- work out what one Azure credential actually reaches.

Credential-first, not tenant-first: you have a leaked service principal secret,
storage key, SAS token or connection string, usually with no directory read, and
the question is what it touches. Read-only, rate limited, fully audited.

  azure-reach.py --cred "$SAS"
      offline only, sends nothing

  azure-reach.py --tenant T --client-id C --client-secret-file s.txt
      live, discovery-only: reports what is visible, touches no subscription

  azure-reach.py --tenant T --client-id C --client-secret-file s.txt
                 --subscriptions SUB --audit run.jsonl
      live, scoped to the subscriptions you are authorized to test
"""

import argparse
import json
import sys

from src import edges, introspect, probes, report, tokens
from src.safety.audit import AuditLog, fingerprint
from src.safety.client import Client, Halt
from src.safety.readonly import ReadOnlyViolation
from src.safety.scope import Gate, OutOfScope
from src.safety.throttle import Throttle


def build_parser():
    p = argparse.ArgumentParser(
        prog="azure-reach", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    p.add_argument("--cred", help="credential material to introspect offline; type auto-detected")
    p.add_argument("--cred-file", help="read it from a file instead of argv")

    p.add_argument("--tenant", help="tenant id, for live checks")
    p.add_argument("--client-id", help="service principal application (client) id")
    p.add_argument("--client-secret", help="client secret; prefer --client-secret-file")
    p.add_argument("--client-secret-file", help="read the secret from a file, not argv")

    p.add_argument("--subscriptions", default="",
                   help="comma-separated subscription ids you are authorized to test. "
                        "Without this the run is discovery-only.")
    p.add_argument("--tenants", default="", help="comma-separated authorized tenant ids")

    p.add_argument("--audit", default="azure-reach-audit.jsonl", help="JSONL audit log path")
    p.add_argument("--stop-file", help="kill switch; checked before every request")
    p.add_argument("--rate", type=float, default=2.0, help="requests/sec, capped at 5")
    p.add_argument("--host-gap", type=float, default=2.0, help="seconds between hits on one host")
    p.add_argument("--max-requests", type=int, default=500, help="hard request budget")
    p.add_argument("--user-agent", default="azure-reach/0.1",
                   help="Entra logs this next to the credential id in sign-in logs")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    return p


SECRET_FLAGS = ("--client-secret", "--cred")


def safe_argv(argv):
    """argv goes into the audit log, and the log must never hold a secret.

    --client-secret and --cred take their value on the command line, so both the
    "--flag value" and "--flag=value" forms have to be scrubbed here. The file
    variants are left intact: a path is not a secret, and knowing which file was
    used is exactly the sort of thing the log exists to record.
    """
    out, skip = [], False
    for arg in argv:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        if arg in SECRET_FLAGS:
            out.append(arg)
            skip = True
        elif any(arg.startswith(flag + "=") for flag in SECRET_FLAGS):
            out.append(arg.split("=", 1)[0] + "=<redacted>")
        else:
            out.append(arg)
    return out


def read_secret(args):
    if args.client_secret_file:
        with open(args.client_secret_file, encoding="utf-8") as fh:
            return fh.read().strip()
    return args.client_secret


def offline(args):
    material = args.cred
    if args.cred_file:
        with open(args.cred_file, encoding="utf-8") as fh:
            material = fh.read()
    parsed = introspect.detect(material.strip())

    if args.json:
        print(json.dumps(parsed, indent=2))
    else:
        print(report.render_introspection(parsed))
        print()
        print(report.render_footprint(None, network_used=False))
    return parsed


def live(args, parsed):
    secret = read_secret(args)
    subs = [s for s in args.subscriptions.split(",") if s.strip()]
    gate = Gate(subscriptions=subs, tenants=[t for t in args.tenants.split(",") if t.strip()])

    audit = AuditLog(args.audit, args.user_agent, argv=safe_argv(sys.argv[1:]),
                     cred_fp=fingerprint(secret))
    client = Client(audit, Throttle(args.rate, args.host_gap), gate, args.user_agent,
                    stop_file=args.stop_file, max_requests=args.max_requests)
    tok = tokens.TokenSource(client, args.tenant, args.client_id, secret)

    status = "ok"
    findings, found_edges = [], []
    reach = edges.empty_reach()
    if parsed and parsed.get("service") == "storage":
        # A storage account key as the input is itself an escalation trigger.
        reach["data_access"].add("storage_keys")
    try:
        # The token tells us who we are, so stage 1 does not have to guess. Its
        # roles claim also names every application permission for free.
        claims = introspect.jwt(tok.get(tokens.GRAPH))
        ctx = {"app_id": claims.get("app_id") or args.client_id,
               "object_id": claims.get("object_id"),
               "tenant": claims.get("tenant") or args.tenant,
               "app_roles": claims.get("app_roles") or []}
        findings, reach = probes.run_all(client, tok, ctx, gate,
                                         authorized_subscriptions=subs, reach=reach)
        found_edges = edges.evaluate(reach)
    except Halt as exc:
        status = "halted"
        sys.stderr.write("[azure-reach] halted: %s\n" % exc)
    except (ReadOnlyViolation, OutOfScope) as exc:
        status = "refused"
        sys.stderr.write("[azure-reach] refused: %s\n" % exc)
    except tokens.TokenError as exc:
        status = "auth-failed"
        sys.stderr.write("[azure-reach] authentication failed: %s\n" % exc)
    finally:
        audit.close(status=status)

    if args.json:
        print(json.dumps({"introspection": parsed,
                          "findings": [f.as_dict() for f in findings],
                          "edges": [e.as_dict() for e in found_edges]}, indent=2))
    else:
        print()
        print(report.render_findings(findings))
        print()
        print(report.render_edges(found_edges))
        print()
        print(report.render_footprint(audit, network_used=True))
        if gate.discovery_only:
            print()
            print("discovery-only: no --subscriptions given, so nothing scoped to a "
                  "subscription was touched.")
    return 0 if status == "ok" else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    live_args = (args.tenant, args.client_id, read_secret(args))

    if not any(live_args) and not (args.cred or args.cred_file):
        sys.stderr.write("[azure-reach] give --cred/--cred-file, or "
                         "--tenant/--client-id/--client-secret\n")
        return 2
    if any(live_args) and not all(live_args):
        sys.stderr.write("[azure-reach] live checks need all of --tenant, --client-id "
                         "and --client-secret\n")
        return 2

    parsed = None
    try:
        if args.cred or args.cred_file:
            parsed = offline(args)
    except (ValueError, OSError) as exc:
        sys.stderr.write("[azure-reach] %s\n" % exc)
        return 2

    if all(live_args):
        return live(args, parsed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
