# Introduction

## Vision

Build the world's most trusted AI-native application security platform.

## Mission

Secure software at AI speed.

## What Vigilloo is

Vigilloo is an **AI Security Engineer**, not a pattern-matching scanner. The difference is
concrete and testable:

| A scanner says | Vigilloo says |
| --- | --- |
| "`whereRaw()` at line 42 - possible SQL injection" | "`POST /orders/search` → `OrderController@search` → `$request->input('sort')` reaches `whereRaw()` at `OrderRepository.php:42` with no binding and no validation on the path. The route carries `auth` middleware, so exploitation needs a session. CWE-89. Here is the parameterised rewrite." |

The second answer requires the route table, the middleware stack, the call graph, the taint
path, and the framework's escaping semantics. That is what the knowledge graph exists for.
Everything else in these docs follows from it.

## Why Laravel first

v0.1 targets **PHP 8.1+ / Laravel 9-11 exclusively**. This is deliberate:

- Laravel is convention-heavy, so routes, controllers, models and middleware are *discoverable*
  rather than guessable. The graph gets high-quality framework semantics cheaply.
- Graph-based security tooling for PHP/Laravel is thin compared to JS and Python, while the
  ecosystem is heavily represented in real-world incident data.
- Laravel has a distinct set of framework-specific vulnerability classes - mass assignment,
  `$guarded = []`, `VerifyCsrfToken::$except`, unsigned routes, missing policies on route model
  binding, `APP_DEBUG` in production - that language-generic scanners miss entirely.
- One language means one Tree-sitter grammar, one package manager (Composer), one advisory
  feed. The pipeline gets proven end to end before it gets wide.

Breadth is a v1.0+ concern. See [24-roadmap](../24-roadmap/README.md).

## Principles

1. **Evidence-first.** Every finding carries a machine-checkable path through the graph:
   source node → propagation edges → sink node. No path, no finding.
2. **Deterministic before probabilistic.** Scanners find and prove. The LLM explains, ranks
   and patches. An LLM is never the sole reason a finding exists.
3. **Graph-based.** Files and regexes do not compose; graphs do. Cross-file, interprocedural
   reasoning is the default, not an upgrade.
4. **Framework-aware.** `$request->all()` is meaningless without knowing Laravel. Adapters
   teach the graph what the framework guarantees and what it does not.
5. **Plugin-first.** Languages, frameworks, scanners, reporters, AI providers and attack
   modules are plugins. Core stays small.
6. **Offline-capable.** Full static analysis with zero network access and zero API keys.
   AI and advisory feeds are enrichment, never a hard dependency.
7. **Safe by default.** Nothing intrusive runs without explicit per-target authorization.
8. **Explainable.** A developer who disagrees with a finding must be able to see exactly why
   Vigilloo believes it, and disprove it.

## Reading order

| Doc | Read it for |
| --- | --- |
| [01-prd](../01-prd/README.md) | Users, requirements, what ships and what does not |
| [02-architecture](../02-architecture/README.md) | How the subsystems fit together |
| [03-parser](../03-parser/README.md) → [07-call-graph](../07-call-graph/README.md) | The analysis pipeline, in execution order |
| [08-framework-adapters](../08-framework-adapters/README.md) | The Laravel adapter - the heart of v0.1 |
| [13-security-engine](../13-security-engine/README.md) | Rules and detection |
| [09-ai-engine](../09-ai-engine/README.md), [10-rag](../10-rag/README.md) | The AI layer and its guardrails |
| [11-plugin-sdk](../11-plugin-sdk/README.md) | Extending anything |
| [17-database](../17-database/README.md), [19-cli](../19-cli/README.md) | Persistence and the user-facing surface |

## Glossary

- **Source** - an expression producing attacker-controlled data (`$request->input('x')`).
- **Sink** - an expression where untrusted data causes harm (`DB::statement($sql)`).
- **Sanitizer** - an operation making tainted data safe for a *specific* sink class. `e()`
  sanitizes for HTML, not for SQL; taint is tracked per kind.
- **Propagator** - an operation passing taint through (assignment, concatenation, array write).
- **Entry point** - a node where external input enters: route, console command, queue job,
  event listener, scheduled task.
- **Reachability** - whether a sink is callable from an entry point.
- **Finding** - a proven or suspected issue with an evidence path attached.
