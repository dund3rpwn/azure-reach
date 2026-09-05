# azure-reach

Work out what one leaked Azure credential actually reaches.

Existing Azure tooling is *tenant-first*: ROADrecon, AzureHound, MicroBurst and
friends assume you have a user context plus directory read, and map the tenant.
CloudFox answers the "what can these creds do" question properly but only for
AWS and GCP.

The situation this is built for is the other one — you have a single service
principal secret, storage key, SAS token or connection string out of a bundle, a
repo, or a DRP alert, usually with no directory read at all, and you need to know
what it touches before you decide whether it matters.

## Two things it does differently

**A 200 does not mean access.** An Azure service principal can read *itself* with
zero permissions assigned. Any tool that reports that as "directory read
confirmed" is producing a false positive. Every check here is a pair — the probe,
plus a control that must fail if the permission is absent — and the output says
which rung it earned:

| verdict | meaning |
| --- | --- |
| `VERIFIED` | the probe passed and its control behaved correctly |
| `VERIFIED NEGATIVE` | explicit 403; the permission is proven absent |
| `ASSUMED` | the probe passed, but no valid control exists (the self-read) |
| `INCONCLUSIVE` | 404, timeout, ambiguous |
| `NOT TESTED` | claimed by the credential, never exercised |

`ASSUMED` is the point of the whole tool.

Two response shapes drive this, and both are things Azure hands out for free:

- **A service principal can read its own object with nothing granted.** So the
  self-read is not a probe here, it is the *control* for directory read. If
  reading yourself works and listing anyone else does not, the 200 is proven to
  be the zero-permission artifact rather than evidence of access.
- **A principal with no role assignments gets `200 {"value": []}` from
  `/subscriptions`, not a 403.** A successful response meaning no access at all.

- **A container's `publicAccess` setting is configuration, not reachability.**
  Every container claiming anonymous access gets fetched with no credential at
  all, because a network rule or the account-level flag can quietly override it.
  The flag is a claim; the unauthenticated fetch is the proof, and it works in
  both directions -- config that says public but is not, and config you would
  otherwise have taken on trust.
- **A vault authorizes by RBAC or by access policy, never both.** Checking one
  model and reporting "no access" on the other is a false negative, so the vault
  probe just asks the vault, and the control-plane listing only says which model
  answered. If the principal sits in an access policy on a vault running RBAC,
  that gets called out as a vestigial policy rather than a bare 403.

There is a third case worth keeping straight in the other direction:
`Microsoft.Authorization/*/read` is a separate permission from the access it
describes, so being unable to *enumerate* your role assignments does not mean you
hold none. That comes back `INCONCLUSIVE`, never `VERIFIED NEGATIVE`.

**The noise is not where people think.** Azure's Activity Log does not record
control-plane reads — GET and LIST are simply absent by default. But Entra
service principal sign-in logs record *every* `client_credentials` token
acquisition, along with `ClientCredentialKeyID` (which secret you used) and
`UserAgent` (what spoke), and those entries cannot be altered or deleted.

So the loud part is authenticating, not enumerating. The tool acts on that: it
does all offline work before touching the network, acquires the minimum number of
tokens, reuses them across every check, and lets you set the User-Agent
deliberately rather than shipping whatever an SDK stamps on.

## Stage 0 is free

Introspection is entirely offline. A JWT or SAS token usually answers most of the
question on its own, at the cost of zero sign-in events:

```
$ ./azure-reach.py --cred "sv=2022-11-02&ss=bfqt&srt=sco&sp=rl&se=2027-01-01T00:00:00Z&spr=https&sig=..."
credential type : sas
signed version  : 2022-11-02
services        : blob, file, queue, table
resource types  : service, container, object
permissions     : read, list
expires         : 2027-01-01T00:00:00Z (2816h left)

declared capability (NOT TESTED):
  - read
  - list

footprint: no requests sent. Nothing to correlate in sign-in logs, Activity Log
or Graph activity logs.
```

## Usage

Two modes. Offline introspection needs only the credential; live checks need a
service principal to authenticate as.

```
# offline -- parses the credential, sends nothing at all
./azure-reach.py --cred "$SAS_TOKEN"
./azure-reach.py --cred-file leaked.txt --json
```

### The two-run workflow

Live runs are deliberately split in two, because you cannot name the
subscriptions you are authorized for before you know any exist.

**First run — discovery.** No `--subscriptions`, so nothing scoped to a
subscription is touched. It tells you who the credential is, what application
permissions it carries, and which subscriptions it can see:

```
./azure-reach.py --tenant "$TENANT" \
                 --client-id "$CLIENT_ID" \
                 --client-secret-file secret.txt
```

**Second run — scoped.** Take the subscription ids from the first run, get
authorization for them, then name them. Only those are probed, even if the
credential can see more:

```
./azure-reach.py --tenant "$TENANT" \
                 --client-id "$CLIENT_ID" \
                 --client-secret-file secret.txt \
                 --subscriptions "$SUB_A,$SUB_B" \
                 --audit run-2026-09-05.jsonl
```

Pass the credential to *both* halves to get the offline summary alongside the
live results — and if it is a storage connection string, that also feeds the
storage-key escalation edge before a single request goes out:

```
./azure-reach.py --cred-file conn.txt --tenant "$TENANT" ...
```

### Options

| flag | default | what it does |
| --- | --- | --- |
| `--cred`, `--cred-file` | — | credential material to introspect offline; type auto-detected |
| `--tenant` | — | tenant id; required for live checks |
| `--client-id` | — | application (client) id |
| `--client-secret`, `--client-secret-file` | — | the secret; prefer the file form |
| `--subscriptions` | *(none)* | comma-separated ids you are authorized to test. Omit for discovery-only |
| `--tenants` | *(none)* | comma-separated authorized tenant ids; refuses to authenticate elsewhere |
| `--audit` | `azure-reach-audit.jsonl` | JSONL log of every request and every refusal |
| `--stop-file` | — | kill switch, checked before every request |
| `--rate` | `2.0` | requests/sec, hard-capped at 5 |
| `--host-gap` | `2.0` | seconds between hits on one host, floor of 1 |
| `--max-requests` | `500` | hard request budget; exceeding it stops the run |
| `--user-agent` | `azure-reach/0.1` | recorded by Entra next to the credential id |
| `--json` | off | machine-readable output |

Prefer `--client-secret-file` over `--client-secret`: an argument is visible in
shell history and to anyone who can run `ps` on the box.

### Stopping a run

Create the kill-switch file. It is checked before *every* request, not once per
host, so a run stops immediately rather than after the current target finishes:

```
touch STOP
./azure-reach.py --stop-file STOP ...
```

### Exit codes

| code | meaning |
| --- | --- |
| `0` | completed |
| `1` | live run did not complete: authentication failed, budget exhausted, kill switch, or a refusal |
| `2` | bad arguments, or the credential could not be parsed |

### Reading the audit log

One JSON object per line, written line-buffered so a hard kill still leaves a
truthful record. `refused` entries are requests the safety layer blocked before
anything was sent, which is what lets the log answer "did you touch X":

```json
{"event":"run_start","user_agent":"azure-reach/0.1",
 "argv":["--tenant","...","--client-secret","<redacted>"],
 "cred_fp":"3ccaad385a032fa1","ts":"...","run_id":"6b4d9a0cf661"}
{"event":"request","method":"POST","url":".../oauth2/v2.0/token","status":200}
{"event":"request","method":"GET","url":".../servicePrincipals?$top=1","status":403}
{"event":"request","method":"GET","url":".../servicePrincipals(appId=...)","status":200,"control":true}
{"event":"refused","method":"GET","url":"https://theirs.blob.core.windows.net/",
 "reason":"not a registered data-plane host"}
{"event":"run_end","status":"ok","requests_sent":4,"token_requests":1}
```

Secrets never appear. A secret passed on the command line is redacted out of
`argv` before the line is written, and the credential itself is recorded only as
`cred_fp`, a truncated SHA-256 — enough to tell two runs apart, or recognise the
same credential months later, without storing it. That is what makes the log
safe to hand to the client, which is the point of keeping one.

## Safety

Read-only is structural, not a promise. A request is built only after its
`(method, host, path)` matches an allowlist; POST is denied by default and
permitted only for the handful of Azure reads modelled as POST, each one listed
explicitly in `src/safety/readonly.py`. The distinction drawn is mutation, not
sensitivity — `listKeys` returns existing keys and is allowed, `regenerateKey`
replaces them and is not. There is no `--confirm-write` flag and there will not
be one.

Also: rate limiting with the ceiling in the code rather than the flag, a kill
switch checked before every request, a hard request budget, and a JSONL audit log
of everything sent — and everything refused — that never contains plaintext
credential material.

**Scope.** Sitting in a tenant is not permission to test it. `GET /subscriptions`
("what exists") always works; `/subscriptions/{id}/...` ("what is inside")
requires that id in `--subscriptions`. A first run tells you what to go and get
authorization for, and sends nothing at any of it.

## Escalation edges

What the credential proves it holds is half the question; what that lets it
reach next is the other half. `data/edges.tsv` is the rule set -- adding an edge
is a data change, not a code change -- and matching joins held roles against the
resource types actually visible in scope. Contributor on its own fires nothing;
Contributor *plus a VM in the same scope* reaches that VM's managed identity.

Application permissions come from the `roles` claim on the token already held,
so naming them costs nothing beyond the sign-in that had to happen anyway.

Every edge is reported with what triggered it and the caveat that qualifies it,
and **none are taken**. Key Vault contents in particular are queued as inputs
for a deliberate second run rather than followed, because auto-recursion turns
one authorized test into an unbounded one and multiplies the sign-in events that
are the loud part.

## Lab

Every claim above is reproducible. `lab/` is Terraform for a deliberately
misconfigured subscription: an over-privileged service principal, a control
principal with **no roles and no app roles**, a storage account with one
anonymously readable container, and two key vaults -- one on Azure RBAC, one on
the legacy access policy model, because a tool that checks one and not the other
reports a false negative on the second.

The control principal is the important one. It holds nothing, but it can still
read its own service principal object, because Entra permits that by default.
That read is what makes naive tooling claim directory access off a 200.

```
cd lab && terraform init && terraform apply
```

Free except the optional VM, which is off by default. See `lab/README.md`.

## Requirements

Python 3.8+. Nothing else — no pip, no venv, no SDK. That is deliberate: the
SDKs and `az` transmit on your behalf, which makes honest request accounting
impossible.

## Tests

```
python -m unittest discover -s tests
```

## Status

Stage 0 (offline introspection), the safety layer, the Terraform lab and the
ARM, Graph, Key Vault and storage probes are done, as are the escalation-edge
rules, with 80 tests covering them. What remains is running the whole thing
against the lab in a real subscription.

Secret values are never read. The Key Vault list operation returns names and
metadata but no values, and that is where this stops -- proving you can list
is the finding, pulling the contents is exfiltration nobody asked for.
Reachable secrets are reported as recursion targets and left alone.
