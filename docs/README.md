# Vigilloo

> Secure software at AI speed.

**Vigilloo** - from Latin *vigil*, watchman - is an AI-native application security platform.
Not another vulnerability scanner: an autonomous AI Security Engineer that builds a knowledge
graph of an application, reasons over data flow, proves exploitability, and explains every
finding with evidence.

This repository holds the **architecture and specification documents** in `docs/`, and the
implementation in `src/`. The first vertical slices are merged: PHP parsing and symbol
extraction, the Laravel route table with its middleware stack, the call graph, kind-based
interprocedural taint for the `sql`, `html` and `mass_assign` kinds, Eloquent model
configuration, policy discovery, the four rules `php.sql-injection`, `php.xss`,
`laravel.mass-assignment` and `laravel.missing-authorization` with their evidence paths, and a
workspace whose SQLite store records every scan. Everything beyond those slices is still spec
only.

## Current target

**v0.1 scans PHP 8.1+ / Laravel 9-11**, fully offline, with no AI required.
[Webisters](https://github.com/webisters) follows in v0.5 as the second PHP adapter. Depth
before breadth - see [24-roadmap](24-roadmap/README.md) for how the rest arrives.

## Documents

### Foundation

| # | Document | Contents |
| --- | --- | --- |
| 00 | [Introduction](00-introduction/README.md) | Vision, principles, why Laravel first, glossary |
| 01 | [PRD](01-prd/README.md) | Users, functional and non-functional requirements, non-goals |
| 02 | [Architecture](02-architecture/README.md) | Subsystems, pipeline, data contracts, failure policy |

### Analysis pipeline

| # | Document | Contents |
| --- | --- | --- |
| 03 | [Parser](03-parser/README.md) | Tree-sitter, PHP symbols, Blade handling, caching |
| 04 | [Knowledge Graph](04-knowledge-graph/README.md) | Layers, node/edge model, storage, export |
| 05 | [Data Flow Analysis](05-data-flow-analysis/README.md) | CFG, SSA, function summaries, precision limits |
| 06 | [Taint Analysis](06-taint-analysis/README.md) | **Canonical PHP/Laravel source-sink-sanitizer reference** |
| 07 | [Call Graph](07-call-graph/README.md) | Resolution strategies, facades, container bindings, entry points |
| 08 | [Framework Adapters](08-framework-adapters/README.md) | **The Laravel adapter** - routes, models, policies, Blade, config |

### Detection and reasoning

| # | Document | Contents |
| --- | --- | --- |
| 13 | [Security Engine](13-security-engine/README.md) | Rule model, rule kinds, OWASP coverage, suppression |
| 09 | [AI Engine](09-ai-engine/README.md) | Providers, context assembly, validation gate, privacy |
| 10 | [RAG](10-rag/README.md) | Knowledge corpus, chunking, hybrid retrieval, grounding |

### Interfaces

| # | Document | Contents |
| --- | --- | --- |
| 19 | [CLI](19-cli/README.md) | Commands, flags, exit codes, configuration |
| 12 | [MCP](12-mcp/README.md) | Tools for AI coding agents |
| 11 | [Plugin SDK](11-plugin-sdk/README.md) | Extension interfaces, declarative rules, testing |
| 16 | [Reporting](16-reporting/README.md) | Markdown, JSON, SARIF, HTML, determinism |
| 17 | [Database](17-database/README.md) | SQLite schema, IDs, fingerprints, migrations |
| 18 | [API](18-api/README.md) | Python API, future HTTP API |

### Later versions

| # | Document | Version |
| --- | --- | --- |
| 14 | [Attack Engine](14-attack-engine/README.md) | v4.0 - authorization model, safe probes |
| 15 | [Runtime](15-runtime/README.md) | v2.0 - monitoring, graph correlation |
| 20 | [Desktop](20-desktop/README.md) | v2.0 - PySide6 app |
| 21 | [Cloud](21-cloud/README.md) | v3.0 - hosted platform, open-core boundary |

### Process

| # | Document | Contents |
| --- | --- | --- |
| 22 | [Testing](22-testing/README.md) | Benchmark corpus, precision gates, determinism |
| 23 | [Dev Guide](23-dev-guide/README.md) | Setup, layout, standards, adding rules |
| 24 | [Roadmap](24-roadmap/README.md) | v0.1 → v5.0, sequencing rules |

## The idea in one example

```
🔴 Critical - SQL Injection in OrderRepository::search
app/Repositories/OrderRepository.php:42 · CWE-89 · A03:2021

1. routes/api.php:23            POST /api/orders/search  [auth:sanctum]
2. OrderController.php:41       $sort = $request->input('sort')      ← source
3. OrderController.php:44       $this->orders->search($q, $sort)     ← arg 0
4. OrderRepository.php:42       ->orderByRaw("created_at {$sort}")   ← sink, unsanitized
```

Every step is a real edge in the graph. That path - not the line number - is the product.

## Stack

Python 3.13+ · Typer / Rich / Textual · Tree-sitter · NetworkX · SQLite · LanceDB · PySide6 ·
pytest · MkDocs Material

## Licence

**Proprietary and confidential. All rights reserved** - see [LICENSE](../LICENSE). Access to
this repository grants no right to use it, and no part of Vigilloo is published under an
open-source licence today. Portions ship under free and paid commercial terms, set out in the
applicable service agreement.

[21-cloud](21-cloud/README.md) documents an open-core boundary - which layers could be opened
and which stay commercial - as a **v3.0 decision**, recorded early so it is not expensive to
move later. It describes a possible future split, not the current licence.
