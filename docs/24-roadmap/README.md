# Roadmap

Version ordering follows the Architecture Bible §15. Each release is defined by a **capability
that works end to end**, not by a feature checklist - a half-built graph engine in three
versions is worth less than a complete one in a single release.

## v0.1 - Laravel static analysis

The whole pipeline, one language, one framework, no AI required.

- PHP 8.1+ parsing via Tree-sitter; symbols, imports, PSR-4 resolution
- Laravel 9/10/11 adapter: routes, middleware, models, policies, Blade, config, facades
- Knowledge graph: AST, symbol, call, CFG, data flow, dependency layers in SQLite
- Taint analysis with the full PHP/Laravel source-sink-sanitizer vocabulary
- Deterministic rule set: injection, XSS, access control, mass assignment, CSRF, secrets,
  misconfiguration, Composer advisories
- `vigilloo scan | review | graph | explain | deps | secrets | baseline | doctor | init`
- Markdown, JSON, terminal reports
- Incremental scanning

**Ships when:** the [22-testing](../22-testing/README.md) corpus gates pass - 100% of seeded
findings, ≥90% precision on real applications, clean runs on 10 open-source Laravel apps.

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

## v1.0 - Integration and breadth

The version where Vigilloo becomes part of a team's workflow rather than a tool someone runs.

- **MCP server** - the agent workflow ([12-mcp](../12-mcp/README.md))
- SARIF 2.1.0 + GitHub code scanning
- GitHub App / Action, GitLab CI, generic CI recipes; PR review comments
- Pre-commit hooks
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

## v2.0 - Desktop and runtime

- PySide6 desktop application ([20-desktop](../20-desktop/README.md))
- Runtime monitoring ([15-runtime](../15-runtime/README.md)) with graph correlation
- Server, container and Kubernetes auditing (`vigilloo server`)
- Java/Kotlin (Spring Boot) and C# (ASP.NET Core)
- PDF reporting

## v3.0 - Cloud

- Hosted platform ([21-cloud](../21-cloud/README.md)): organisations, teams, SSO, RBAC
- Continuous monitoring, trends, policy enforcement
- The commercial tier; the CLI stays open source and fully capable offline

## v4.0 - Attack engine

- Safe, authorization-gated exploit validation ([14-attack-engine](../14-attack-engine/README.md))
- Static findings upgraded from "likely" to "confirmed" with request/response evidence
- Attack path chaining across the graph

## v5.0 - Autonomous security engineering

- Continuous autonomous review across an organisation's repositories
- Threat intelligence correlation
- Compliance automation (SOC 2, ISO 27001, PCI DSS evidence collection)
- Security copilot over the full graph

## Sequencing rules

**Depth before breadth.** Laravel done properly beats twelve frameworks done shallowly. Language
two ships only after language one meets its precision targets - a second language built on an
unproven pipeline just doubles the debt.

**Deterministic before AI.** v0.1 has no AI dependency at all. This ordering is deliberate: it
forces the deterministic engine to be genuinely good, rather than letting an LLM paper over its
gaps.

**Nothing intrusive before v4.0.** The attack engine is last, not because it is hardest, but
because shipping it early to a small team with an immature authorization model is how a security
tool becomes an incident.

**Open core throughout.** CLI, SDK, plugins, MCP and the graph engine stay open source at every
version. Only the cloud, collaboration, compliance and fleet-management layers are commercial.
