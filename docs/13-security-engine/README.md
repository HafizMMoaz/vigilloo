# Security Engine

Runs rules over the knowledge graph and emits findings. **Fully deterministic** - same graph,
same ruleset, same findings, every time, with no network and no LLM. The AI engine consumes its
output; it never contributes to it.

## Rule shape

```python
@dataclass
class Rule:
    id: str                    # "laravel.mass-assignment" - stable forever, it is a public API
    title: str
    severity: Severity         # critical | high | medium | low | info
    confidence: float          # base confidence before path evidence adjusts it
    cwe: list[str]
    owasp: list[str]           # "A03:2021"
    kind: RuleKind             # TAINT | STRUCTURAL | CONFIG | DEPENDENCY | SECRET
    languages: list[str]
    frameworks: list[str]
    remediation: str           # deterministic guidance, present with or without AI
```

Rule IDs are permanent. They appear in SARIF, in baselines, and in `// vigilloo-ignore` comments
in users' code. Renaming one silently un-suppresses findings across every codebase using it.

## Rule kinds

### 1. Taint rules

Source → sink with no adequate sanitizer, per [06-taint-analysis](../06-taint-analysis/README.md).
Declarative:

```yaml
id: php.sql-injection
severity: critical
cwe: [CWE-89]
owasp: ["A03:2021"]
taint_kind: sql
sources: [laravel.request.*, php.superglobal.*]
sinks: [laravel.db.raw, laravel.query.where_raw, php.pdo.query, php.mysqli.query]
sanitizers: [php.intval, laravel.query.binding, php.cast.int]
require_reachable_from: [route, command, job]
```

Severity is then adjusted by real evidence:

| Evidence | Adjustment |
| --- | --- |
| Reachable from an unauthenticated route | +1 severity |
| Reachable only from a console command | −1 severity |
| Any path edge below 0.5 confidence | −1 severity, marked "needs review" |
| Partial sanitizer on the path (e.g. `addslashes`) | keep severity, note the weak control |
| Sink inside `vendor/` | suppressed by default |

### 2. Structural rules

Graph shape, no taint required. Where the Laravel-specific value concentrates.

- Route with model binding + `auth` + no policy check → **IDOR**
- State-changing route (POST/PUT/PATCH/DELETE) with no auth middleware
- `VerifyCsrfToken::$except` containing wildcards or state-changing paths
- Model with `$guarded = []` reachable from a mass-assignment sink
- Auth endpoints (login, register, password reset) with no `throttle`
- Policy method defined but never referenced by any route or action - dead authorization
- Public action route (unsubscribe, confirm, approve) without `signed`
- `authorize()` present in one action of a resource controller but absent in its siblings -
  inconsistency is a strong signal of an oversight rather than an intentional choice

### 3. Configuration rules

`.env`, `config/*.php`, `php.ini` hints, `Dockerfile`, `docker-compose.yml`, web server config.

`APP_DEBUG` in production, missing/committed/default `APP_KEY`, insecure session cookie flags,
`TRUSTED_PROXIES=*`, permissive CORS (`allowed_origins: ['*']` with credentials), `.env` tracked
in git, `storage/` or `.git/` inside the web root, directory listing enabled, missing security
headers (HSTS, CSP, `X-Frame-Options`, `X-Content-Type-Options`).

### 4. Secret rules

High-entropy strings plus provider-specific patterns (AWS `AKIA…`, Stripe `sk_live_…`, GitHub
`ghp_…`, Google, Slack, JWT, private-key PEM blocks, database URLs with inline passwords).

Entropy alone is unusable - it fires on hashes, UUIDs, base64 assets and test fixtures. The
filter chain is: provider pattern match → entropy threshold → context (variable name, is it in a
test/fixture/example file) → checksum validation where the format allows it (AWS keys and Stripe
keys have verifiable structure). `.env.example` with placeholder values is not a finding;
`.env` tracked in git is a critical one.

### 5. Dependency rules

`composer.lock` → exact versions → advisories → **reachability check against the call graph**.
That last step is the differentiator: "47 vulnerable packages" is noise, "3 vulnerable packages
with a vulnerable function reachable from a public route" is a work queue. Ranking uses CVSS,
EPSS (exploitation probability), CISA KEV membership, and reachability together.

Also: abandoned packages, packages with no releases in 3+ years, and license risk (GPL in a
proprietary codebase) as informational output.

## Coverage - OWASP Top 10 (2021)

| Category | v0.1 coverage |
| --- | --- |
| A01 Broken Access Control | Route/policy structural rules, IDOR, unauthenticated state change, CSRF gaps |
| A02 Cryptographic Failures | Weak hashing, hardcoded keys, insecure cookies, weak randomness (`rand`/`mt_rand` for tokens) |
| A03 Injection | SQL, command, code, LDAP, XPath, header, template injection, XSS |
| A04 Insecure Design | Partial - missing rate limits, missing authorization patterns |
| A05 Security Misconfiguration | `APP_DEBUG`, headers, CORS, exposed files, default credentials |
| A06 Vulnerable Components | Composer advisories + reachability |
| A07 Auth Failures | Missing throttle, weak password policy, session fixation, insecure "remember me" |
| A08 Integrity Failures | `unserialize` of untrusted input, unsigned URLs, unpinned dependencies |
| A09 Logging Failures | Secrets written to logs, log injection, missing auth-event logging |
| A10 SSRF | HTTP-client sinks with user-controlled URLs |

## Finding output

```text
Finding
  id                  stable: sha1(rule_id : file_path : normalized_span : path_signature)
  rule_id, severity, confidence
  title, description, remediation
  location            file, line, column, span
  evidence_path[]     source → … → sink, every step a real graph node
  cwe[], owasp[], references[]
  fingerprint         location-independent, for baseline matching across refactors
```

Two IDs, deliberately. `id` is exact and changes when the code moves. `fingerprint` is derived
from rule + normalized code shape + enclosing symbol name, so a finding survives reformatting
and line shifts - which is what makes baselines usable in a real repo where code moves constantly.

## Suppression

| Mechanism | Scope |
| --- | --- |
| `// vigilloo-ignore rule-id -- justification` | Next line. Justification is **required**; a bare ignore is itself reported. |
| `vigilloo.yml` `suppress:` | Path glob + rule, with an expiry date |
| Baseline file | Everything currently failing, so a team can gate new findings without fixing the backlog first |

Expiring suppressions matter: a permanent ignore is how a security backlog becomes invisible.

## Execution

Rules run in parallel over the graph. Per-file rules parallelise by file; taint rules by entry
point. A rule that throws is disabled for the run and recorded in the manifest - one broken
rule must never fail a scan.

Ordering is fixed (by rule ID) so output is deterministic regardless of scheduling, satisfying
NFR-7.

## Deduplication

Multiple entry points reaching one sink produce one finding with several paths, not several
findings. The shortest, highest-confidence path is shown; the rest are attached. Without this,
one bad helper called from thirty controllers reports thirty times and the report is unreadable.
