# Product Requirements Document

Scope of this document: **v0.1 through v1.0**. Later versions are sketched in
[24-roadmap](../24-roadmap/README.md) and are not specified here.

## Users

| User | Primary job | What success looks like |
| --- | --- | --- |
| **Laravel developer** | Fix real bugs before review | `vigilloo scan` in under 60s on a mid-size app, zero setup, findings they agree with |
| **Tech lead / reviewer** | Gate PRs without becoming the bottleneck | `vigilloo review --diff` comments only on code the PR actually changed |
| **DevSecOps** | Wire security into CI without noise | SARIF into GitHub code scanning, deterministic exit codes, tunable severity gate |
| **Security engineer / pentester** | Understand attack surface fast | Route inventory, taint paths, `vigilloo graph` export into their own tooling |
| **OSS maintainer** | Keep a package clean for free | Runs fully offline, no account, no telemetry |

Enterprise buyers are a v3.0 concern ([21-cloud](../21-cloud/README.md)). Nothing in v0.1-v1.0
should be designed around them.

## Functional requirements

### FR-1 Project detection

Detect PHP + Laravel from `composer.json` (`laravel/framework` requirement), directory shape
(`app/`, `routes/`, `bootstrap/app.php`) and Laravel major version. Refuse clearly and
usefully on unsupported stacks - never half-analyse a Symfony app and emit garbage.

### FR-2 Knowledge graph

Build AST, symbol, call, control-flow, data-flow and dependency graphs for the whole project.
Persist to SQLite so a second run is incremental. Export GraphML / DOT / GEXF / JSON.

### FR-3 Framework semantics

The Laravel adapter must resolve, at minimum:
route table (URI, verb, middleware, controller action, name), controller actions, middleware
groups and aliases, Eloquent models with `$fillable` / `$guarded` / `$casts` / relationships,
form requests and their rules, policies and gates, Blade templates and their escaping mode,
facade → concrete class mapping, service-container bindings, config and `.env` usage,
queue jobs, console commands, event listeners, scheduled tasks.

### FR-4 Deterministic detection

Taint-based and structural rules across: injection (SQL, command, code, LDAP, XPath), XSS
(reflected/stored via Blade), path traversal, SSRF, open redirect, insecure deserialization,
mass assignment, broken access control (missing `auth`/policy on routes and bound models),
CSRF gaps, secrets in source and `.env`, weak crypto, insecure file upload, misconfiguration
(`APP_DEBUG`, `APP_KEY`, session/cookie flags), and vulnerable Composer dependencies.

### FR-5 AI reasoning

Given a deterministic finding, produce: a plain-language explanation grounded in the evidence
path, an exploitability assessment, a suggested patch as a unified diff, and a confidence
score. Must degrade gracefully to deterministic-only output when no provider is configured.

### FR-6 Reporting

Markdown (human), JSON (machines), SARIF 2.1.0 (CI), HTML (shareable). Stable finding IDs
across runs so results can be diffed, baselined and suppressed.

### FR-7 Git and CI integration

Scan a working tree, a commit range, or a PR diff. Exit codes suitable for pipeline gating.
GitHub Action and generic CI recipe.

### FR-8 MCP server

Expose analysis over MCP so coding agents (Claude Code, Cursor, Codex, Cline, Roo Code) can
query the graph and review their own output before a human sees it. See [12-mcp](../12-mcp/README.md).

### FR-9 CLI

See [19-cli](../19-cli/README.md) for the full surface.

## Non-functional requirements

| ID | Requirement | Target |
| --- | --- | --- |
| NFR-1 | **Cold scan performance** | ≤ 60 s for 100k LOC on 4 cores; ≤ 5 min for 1M LOC |
| NFR-2 | **Incremental scan** | ≤ 5 s for a 20-file diff against a warm cache |
| NFR-3 | **Memory** | ≤ 2 GB RSS at 500k LOC |
| NFR-4 | **Offline** | Every FR except FR-5 and advisory refresh works with no network |
| NFR-5 | **Cross-platform** | Linux, macOS, Windows; Python 3.13+; no compiler needed to install |
| NFR-6 | **Precision** | ≥ 90% true-positive rate on the Laravel benchmark corpus ([22-testing](../22-testing/README.md)) |
| NFR-7 | **Determinism** | Same input + same ruleset ⇒ byte-identical JSON report, AI layer excluded |
| NFR-8 | **Safety** | No network egress to the analysed app, no code execution, no writes outside the workspace, unless explicitly authorized |
| NFR-9 | **Privacy** | Source leaves the machine only when the user configures a remote AI provider, and only the minimum slice |
| NFR-10 | **Extensibility** | A new scanner is a plugin file; no core edit, no rebuild |

## Explicit non-goals for v0.1

- Languages other than PHP; frameworks other than Laravel.
- Runtime, container, cloud and network scanning.
- Any intrusive behaviour - the attack engine ships disabled.
- Desktop GUI, cloud service, team features, compliance reporting.
- Auto-applying patches. Vigilloo proposes; humans apply.

## Acceptance criteria for v0.1

1. Clean run on 10 real open-source Laravel applications with no crash and no timeout.
2. Every seeded vulnerability in the benchmark corpus detected, with a correct evidence path.
3. False-positive rate ≤ 10% on the same corpus, reviewed by hand.
4. Full scan works with the network interface down.
5. `vigilloo scan --format sarif` output validates against the SARIF 2.1.0 schema and renders
   in GitHub code scanning.
