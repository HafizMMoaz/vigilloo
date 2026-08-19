# Roadmap

Version ordering follows the Architecture Bible §15. Each release is defined by a **capability
that works end to end**, not by a feature checklist - a half-built graph engine in three
versions is worth less than a complete one in a single release.

## v0.1 - Laravel static analysis

The whole pipeline, one language, one framework, no AI required.

This table is the implementation-status record for v0.1. `done` means the capability works end
to end; `partial` means some of it ships and the remainder is still specified only; `spec only`
means nothing of it is implemented. Nothing else in the repository restates it - `CLAUDE.md`
summarises and points here.

| Capability | Status | What ships today |
| --- | --- | --- |
| PHP 8.1+ parsing via Tree-sitter; symbols, imports, PSR-4 resolution | partial | Parsing, symbol extraction, file-local imports and PSR-4 autoload resolution from `composer.json`, with mappings that escape the project root refused. Trait declarations, trait composition, `insteadof` / `as` adaptations and inherited methods resolve to the declaration that owns the body. Interfaces, enums and the remaining PHP 8 syntax coverage are still partial. |
| Laravel 9/10/11 adapter: routes, middleware, models, policies, Blade, config, facades | partial | Route table with its per-route middleware stack, Eloquent model configuration, policy discovery, Blade views. Middleware group expansion, `Route::resource`, route groups, config extraction and facade resolution are not implemented. |
| Knowledge graph: AST, symbol, call, CFG, data flow, dependency layers in SQLite | partial | Symbol, call and framework layers. Every scan writes them to the SQLite store under `.vigilloo/` as `nodes` and `edges`: one node per file, class, trait, method, route and named middleware, and `DECLARES`, `EXTENDS`, `USES_TRAIT`, `HANDLES`, `PROTECTED_BY`, `CALLS` and `INSTANTIATES` between them. Call edges cover the receivers the source states outright (`$this`, `self`, `parent`, a class name, a typed property), including inherited and trait-provided methods; facades, variable receivers and plain functions do not resolve and are counted, not guessed. A control flow graph (`src/analysis/cfg.py`: basic blocks, typed edges, `build_cfg`) and SSA construction (`src/analysis/ssa.py`) are built and drive the branch-sensitive taint walk, but neither is persisted to the store as a graph layer. The AST and dependency layers are not built at all. Findings are read back with their complete evidence paths, by scan or by fingerprint across scans; no command surfaces that yet. The stored graph exports to JSON and GraphML, deterministically and without re-scanning; DOT, GEXF and the `--layer`/`--focus`/`--depth` filters of [04-knowledge-graph](../04-knowledge-graph/README.md) are not implemented, and no command surfaces that either. |
| Taint analysis with the full PHP/Laravel source-sink-sanitizer vocabulary | partial | Kind-based interprocedural taint for eleven of the twelve kinds in [06-taint-analysis](../06-taint-analysis/README.md): `sql`, `html`, `shell`, `path`, `url`, `header`, `ldap`, `xpath`, `log`, `code` and `mass_assign` each have their own sinks and sanitizers, and `js` is handled through the Blade context rewrite rather than a sink table of its own. The walk is branch-sensitive over the CFG. Sources are the `Illuminate\Http\Request` methods, magic property reads on a Request (`$request->bio`, the `__get()` form of `input()` and carrying the same kinds, recognised by the receiver rather than by the property name), route parameters bound into a controller signature from the URI (`{slug}` arriving as `$slug`, matched by name and excluding both the coerced scalar types and route-model binding), and PHP's own request superglobals (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$argv`, and `$_SERVER` split per key); the `request('x')` helper and the legacy `Input` facade, both matched on the resolved class rather than the written name so a project's own `Input` is untouched; `$_ENV`, `getenv()`, `php://input` and `apache_request_headers()` are not wired. |
| Deterministic rule set: injection, XSS, access control, mass assignment, CSRF, secrets, misconfiguration, Composer advisories | partial | **30 rules**, each with a complete evidence path. Injection: `laravel.raw-query`, `php.command-injection`, `php.code-execution`, `php.ldap-injection`, `php.xpath-injection`, `php.log-injection`, `php.path-traversal`, `php.ssrf`, `php.open-redirect`. XSS: `php.xss`, `laravel.blade-raw-echo`. Access control: `laravel.missing-authorization`, `laravel.inconsistent-authorization`, `laravel.dead-authorization`, `laravel.unauthenticated-route`, `laravel.unsigned-route`, `laravel.no-throttle`, `laravel.form-request-true`. Mass assignment: `laravel.mass-assignment`, `laravel.validated-bypass`. CSRF: `laravel.csrf-except`. Misconfiguration: `laravel.debug-enabled`, `laravel.app-key`, `laravel.env-outside-config`, `laravel.trusted-proxies`, `laravel.session-cookie`, `laravel.debug-artifact`, `laravel.unsafe-upload`, `laravel.weak-hash`, `laravel.weak-randomness`. Secrets and Composer advisories are spec only. **Precision is unmeasured**: every fixture is synthetic, so the false-positive rate of these 30 rules on real Laravel applications is not known. |
| Suppression: inline comments, `vigilloo.yml` path globs with expiry, baseline files | done | `// vigilloo-ignore <rule-id>` with a justification; a bare ignore is itself reported as `vigilloo.bare-ignore`. `suppress:` entries in `vigilloo.yml` matched by path glob and honouring `expires:`. A baseline file passed as `vigilloo scan --baseline`. |
| User-defined sources and sanitizers via `vigilloo.yml` | done | `taint.sources` and `taint.sanitizers` entries name a function, facade or method by FQN and the kinds it introduces or clears; the walk incorporates them alongside the built-in vocabulary. |
| `vigilloo scan \| review \| graph \| explain \| deps \| secrets \| baseline \| doctor \| init` | partial | `vigilloo scan` only. |
| Markdown, JSON, terminal reports | partial | Terminal report only, and it opens with the scan's own coverage: the parse success and call resolution rates, with the counts they came from, and the constructs that failed to parse named down to the method - `method OrderController::search`, falling back to the file where no named construct encloses the error, capped with the remainder counted. Markdown and JSON are spec only. |
| Incremental scanning | spec only | The store keeps the per-file digest the incrementality key needs; no scan reads it. |

**Ships when:** the [22-testing](../22-testing/README.md) corpus gates pass - 100% of seeded
findings, ≥90% precision on real applications, clean runs on 10 open-source Laravel apps.

**Distance to that gate.** The engine is the far side of v0.1; the surface and the evidence are
not. 30 rules and eleven taint kinds are wired and 398 tests pass over them, but the corpus is
entirely synthetic, so the ≥90% precision criterion has never been evaluated - not failed,
never run. Of the nine commands in [19-cli](../19-cli/README.md) only `scan` exists, and of the
three report formats in [16-reporting](../16-reporting/README.md) only the terminal one does,
which is also why precision cannot yet be measured: there is no machine-readable output to
diff. The plan that closes this is
[docs/plans/2026-08-19-stabilise-measure-ship-v0.1.md](../plans/2026-08-19-stabilise-measure-ship-v0.1.md).

## v0.5 - Reasoning

- AI engine: explanation, exploitability, patch generation, the full validation gate
- RAG corpus (CWE, OWASP, CAPEC, Laravel docs) with the pre-built LanceDB index
- Provider plugins: Anthropic, OpenAI, Gemini, Ollama, Azure, OpenRouter
- Dominator analysis - "one fix here closes twelve findings"
- HTML reports
- Deep data flow: field sensitivity, stored/second-order taint
- **Webisters adapter** ([08-framework-adapters](../08-framework-adapters/README.md)) - second
  PHP framework, reusing the entire v0.1 pipeline. Doubles as the proof that
  `FrameworkAdapter` is genuinely framework-neutral rather than Laravel-shaped.

## v0.7 - Supply Chain

Nothing untrusted lands on a developer's machine without Vigilloo saying so. Fully specified in
[27-supply-chain](../27-supply-chain/README.md).

- **Tier 1 lockfile differ** across every major ecosystem: Composer, npm/pnpm/yarn, PyPI, Cargo,
  Go modules, RubyGems, Maven/Gradle, NuGet. Detects; cannot block.
- **Tier 2 pre-install hooks**, per ecosystem and opt-in: a Composer plugin and an npm wrapper
  enforcing `ignore-scripts`. The only tier that stops code before it executes.
- **Verdict engine** over a vendored OSV advisory database, the existing PHP taint engine turned
  on package source, deterministic typosquat and lifecycle-script heuristics, and an optional
  reputation signal.
- **IDE extension vetting** for VS Code and Open VSX, honestly scoped as advisories plus
  heuristics rather than deep analysis until v1.5 brings a JavaScript engine.
- `PACKAGE` and `EXTENSION` graph nodes, which v1.0 reachability builds on.

**Vigilloo ships no privileged component here or ever.** Host-level install visibility, where an
organisation needs it, comes from Santa or osquery which the customer owns.

**Ecosystem breadth here does not contradict depth-before-breadth.** That rule governs the
analysis engine, where a framework adapter costs the whole
[08-framework-adapters](../08-framework-adapters/README.md) surface. Supply chain operates on
package identity, so its per-ecosystem cost is a lockfile parser and an OSV identifier. SAST
stays Laravel-deep.

## v1.0 - Integration and SCA

The version where Vigilloo becomes part of a team's workflow and tracks external dependencies.

- **MCP server** - the agent workflow ([12-mcp](../12-mcp/README.md))
- SARIF 2.1.0 + GitHub code scanning
- GitHub App / Action, GitLab CI, generic CI recipes; PR review comments
- Pre-commit hooks
- **Deep Software Composition Analysis (SCA)**: uses the call graph to verify *reachability* of
  the vulnerable packages v0.7 identifies, dropping the findings whose vulnerable code no route
  can reach. v0.7 answers "is this package known-bad"; v1.0 answers "is the bad part reachable
  from a route in this application". Same advisory database, one deepening the other.
- **Second language: Python** (Django, FastAPI, Flask)
- More PHP frameworks: Symfony, CodeIgniter
- Plugin SDK published, documented, versioned
- SBOM export (CycloneDX, SPDX)

## v1.5 - JavaScript and TypeScript

- Node adapters: Express, NestJS, Next.js
- Client-side adapters: React, Angular, Vue - a different threat model (DOM XSS, bundle secrets,
  `postMessage`, token storage), sharing the graph with its own sink vocabulary
- Cross-stack flows: a taint path from a React form through an API route into a Laravel sink,
  in one graph

## v2.0 - Attack Surface Monitoring (ASM) and Desktop

- **Attack Surface Monitoring (ASM)** ([25-attack-surface-monitoring](../25-attack-surface-monitoring/README.md)): Subdomain enumeration, port scanning, and exposed endpoint mapping, augmenting the static route table.
- PySide6 desktop application ([20-desktop](../20-desktop/README.md))
- Runtime monitoring ([15-runtime](../15-runtime/README.md)) with graph correlation
- Server, container and Kubernetes auditing (`vigilloo server`)
- Java/Kotlin (Spring Boot) and C# (ASP.NET Core)
- PDF reporting

## v3.0 - Autonomous Red Teaming

- **Attack Engine / Hacking Agent** ([26-autonomous-red-teaming](../26-autonomous-red-teaming/README.md)): A multi-agent framework (similar to Decepticon) that generates Engagement Plans, executes real exploits against target environments in a sandbox, and validates static findings.
- Safe, authorization-gated exploit validation ([14-attack-engine](../14-attack-engine/README.md))
- Static findings upgraded from "likely" to "confirmed" with request/response evidence
- Attack path chaining across the graph

## v4.0 - Offensive Vaccine & Continuous Defense

- **Offensive Vaccine Loop**: Exploit successes from the Red Team engine automatically generate verifiable patching suggestions and regression tests (SAST rules) to immunize the codebase.
- Continuous autonomous review across an organisation's repositories
- Threat intelligence correlation
- Compliance automation (SOC 2, ISO 27001, PCI DSS evidence collection)

## v5.0 - Cloud and Enterprise Management

- Hosted platform ([21-cloud](../21-cloud/README.md)): organisations, teams, SSO, RBAC
- Continuous monitoring, trends, policy enforcement
- The commercial tier; the CLI stays open source and fully capable offline

## Sequencing rules

**Depth before breadth, in the analysis engine.** Laravel done properly beats twelve frameworks
done shallowly. Language two ships only after language one meets its precision targets - a second
language built on an unproven pipeline just doubles the debt. This rule is scoped to analysis,
where breadth costs a framework adapter per framework. It does not govern v0.7 supply chain,
where breadth costs a lockfile parser per ecosystem and buys real coverage immediately; see
[27-supply-chain](../27-supply-chain/README.md).

**No privileged component, at any version.** Vigilloo never ships a daemon, root helper, kernel
extension or system extension. Host-level visibility, where it is needed, is read from Santa or
osquery which the customer installs and owns. A privilege-escalation surface inside a security
tool is not a tradeoff to be revisited later.

**Deterministic before AI.** v0.1 has no AI dependency at all. This ordering is deliberate: it
forces the deterministic engine to be genuinely good, rather than letting an LLM paper over its
gaps.

**Nothing intrusive before v3.0.** The attack engine is late, not because it is hardest, but
because shipping it early to a small team with an immature authorization model is how a security
tool becomes an incident.

**Open core throughout.** CLI, SDK, plugins, MCP and the graph engine stay open source at every
version. Only the cloud, collaboration, compliance and fleet-management layers are commercial.
