# Attack Engine

Converts a static finding into a proven one by testing it against a **running, explicitly
authorized** target.

> **Status: v4.0. Ships disabled. Not implemented in v0.1.**
> Documented now because the authorization model must be designed before any code exists, not
> retrofitted onto a working exploit framework.

## Purpose

Static analysis produces "this looks exploitable". A safe probe produces "this *is* exploitable,
here is the request and the response". That difference decides whether something is fixed this
sprint or next quarter - and it removes the argument about false positives entirely.

## Authorization - the part that matters

No probe runs without all of the following:

1. **An authorization file** at the project root, listing target hosts, allowed time windows,
   an owner contact, and an expiry date. Expired means no run.
2. **Explicit target confirmation** on the command line - the target is never inferred from
   config, `.env`, or anything the tool discovered by itself.
3. **Interactive confirmation** naming the target, unless `--yes` is passed in a context that
   already has recorded authorization.
4. **A scope allowlist.** Hosts not listed are refused. No wildcards, no CIDR ranges wider than
   /24, no following redirects off-scope.
5. **Refusal to target anything not obviously the user's**: public suffix domains that don't
   match the authorization file, cloud metadata endpoints (`169.254.169.254`), and localhost
   only when explicitly listed.

```yaml
# .vigilloo/authorization.yml
version: 1
authorized_by: "Name <email>"
authorized_at: 2026-07-25
expires: 2026-08-25
targets:
  - host: staging.example.com
    scheme: https
    scope: ["/api/**"]
    exclude: ["/api/payments/**"]
allowed_windows: ["Mon-Fri 09:00-17:00 UTC"]
max_requests_per_second: 5
destructive: false          # never true without a separate, explicit flag
```

Every action is logged to an append-only audit file: timestamp, target, probe, request,
response status. This is the record that makes an engagement defensible.

## Safety model

- **Non-destructive by default.** Probes prove a vulnerability class without exercising its
  impact: a time-based SQL sleep rather than `DROP TABLE`; a benign marker reflection rather
  than a stored payload; an SSRF callback to a listener the user controls rather than an
  internal service.
- **Rate limited** by the authorization file, with backoff on 429/503.
- **Reversible.** Anything creating state records how to undo it. Probes that cannot be undone
  require `--destructive`, a separate authorization flag, and a distinct confirmation.
- **No lateral movement, no persistence, no exfiltration.** The engine proves reachability of a
  vulnerability class; it does not pivot, install anything, or retrieve real data volumes.
  Confirming SQLi means retrieving a version string, not a user table.
- **Hard kill switch.** `Ctrl-C` aborts immediately; a heartbeat file lets an operator stop a
  run externally.

## Modules

Each targets one finding class, driven by the static evidence path - the engine knows the route,
the parameter and the sink before it sends anything, so probing is precise rather than a blind
fuzz.

| Module | Proves | Method |
| --- | --- | --- |
| SQLi | CWE-89 | Boolean and time-based differential; version string only |
| XSS | CWE-79 | Unique marker reflection, checked in parsed DOM context |
| SSRF | CWE-918 | Callback to a user-supplied listener |
| Path traversal | CWE-22 | Read a known-benign file, e.g. a marker placed by the operator |
| Open redirect | CWE-601 | Redirect to a user-controlled sentinel host |
| IDOR / access control | CWE-639 | Two authorized accounts, cross-access attempt |
| CSRF | CWE-352 | Cross-origin state change with a benign field |
| Auth | CWE-307 | Rate-limit probing within the configured budget |
| Upload | CWE-434 | Inert file with a distinctive extension, then cleanup |
| API fuzzing | mixed | Schema-aware value fuzzing from the route inventory |

## Output

A probe result attaches to its finding and upgrades `exploitability` from `likely` to
`confirmed`, with the full request/response as evidence. A failed probe is **not** proof of
safety - WAFs, network policy and environment differences all cause false negatives - so a
finding is never downgraded below `likely` on a failed probe. It is annotated
"probe inconclusive", and that distinction is honoured everywhere in the report.

## CLI

```bash
vigilloo attack --target https://staging.example.com --authorization .vigilloo/authorization.yml
vigilloo attack --finding FINDING-ID --target …      # verify one finding
vigilloo attack --dry-run                            # show what would be sent, send nothing
```

`--dry-run` is the default in CI.

## Explicitly out of scope, permanently

Denial of service, resource exhaustion, credential stuffing or brute force beyond configured
rate-limit checks, exploitation of third-party services the target depends on, social
engineering, persistence, and anything against a target not in the authorization file.

These are not "later" items. An application security tool that ships DoS capability is a
liability to its users and to the people running it, regardless of intent.
