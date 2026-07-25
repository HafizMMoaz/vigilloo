# System Architecture

## Shape

One Python process. A pipeline of stages, each consuming the previous stage's output from the
workspace store. No stage calls backwards.

```text
                    ┌──────────────────────────────────────────┐
  vigilloo CLI ─────▶                Workspace                 │
  MCP server   ─────▶   project root, config, SQLite store,    │
                    │   cache, run manifest                    │
                    └────────────────────┬─────────────────────┘
                                         │
   ┌─────────────────────────────────────▼─────────────────────────────────────┐
   │ 1. Detect      composer.json + tree shape → PHP/Laravel, version, layout   │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ 2. Parse       Tree-sitter → AST, symbols, imports          [03-parser]    │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ 3. Enrich      Laravel adapter → routes, models, middleware, [08-adapters] │
   │                policies, Blade, facade map, config                         │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ 4. Graph       call graph, CFG, data-flow graph, dep graph   [04][05][07]  │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ 5. Analyse     taint propagation + structural rules          [06][13]      │
   │                → findings with evidence paths                              │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ 6. Reason      RAG retrieval → LLM → explain, rank, patch    [09][10]      │
   │                (optional; skipped when no provider)                        │
   ├───────────────────────────────────────────────────────────────────────────┤
   │ 7. Report      Markdown / JSON / SARIF / HTML                [16]          │
   └───────────────────────────────────────────────────────────────────────────┘

   Out of band, authorization-gated:
     Attack Engine [14]  ·  Runtime Monitor [15]
```

## The load-bearing decision

**Stages 1-5 are deterministic and self-sufficient.** Stage 6 is optional enrichment.

This is not a style preference. It is what makes the product trustworthy, offline-capable,
reproducible in CI, and cheap to run. Any design that makes a finding *depend* on an LLM
response is wrong. The LLM may explain a finding, rank it, or propose a patch. It may not
create one, and it may not silently delete one - a suppression it proposes is recorded as an
AI opinion attached to the finding, and the finding stays.

## Subsystems

| Subsystem | Responsibility | Does not |
| --- | --- | --- |
| **Workspace** | Own the project root, merged config, SQLite handle, cache, run manifest | Analyse anything |
| **Parser** | Source → AST + symbol table + imports | Know what Laravel is |
| **Framework adapter** | Attach framework semantics to graph nodes | Emit findings |
| **Graph engine** | Build and query the graph layers | Know what a vulnerability is |
| **Security engine** | Run rules over the graph, emit findings + evidence | Call an LLM |
| **AI engine** | Explain, rank, patch, using evidence as context | Invent findings |
| **Reporting** | Serialise findings to output formats | Filter by policy (config does that) |
| **MCP server** | Expose the same engines as tools | Contain its own analysis logic |
| **Attack engine** | Validate exploitability against authorized targets | Run by default |

The rule that keeps this honest: **each subsystem knows only about the one below it.** The
parser has no Laravel awareness; the graph engine has no security awareness; the security
engine has no LLM awareness. Violations of this are the main architectural smell to watch for.

## Data flow contract

Stages communicate through the store, not through in-memory handoffs, so any stage can be
re-run alone against cached upstream output.

```text
Detect  → ProjectProfile        (language, framework, version, roots, entry points)
Parse   → ParsedFile[]          (AST handle, symbols, imports, hash)
Enrich  → FrameworkFacts        (routes, models, middleware, policies, templates, bindings)
Graph   → GraphLayers           (nodes + typed edges, in SQLite)
Analyse → Finding[]             (rule id, severity, location, evidence path, CWE)
Reason  → Finding[] + AIVerdict (explanation, exploitability, patch, confidence)
Report  → bytes
```

`Finding` is the central type. Its shape is fixed in [17-database](../17-database/README.md)
and everything downstream - reports, SARIF, MCP, the desktop app, the cloud - consumes it.
Changing it is a breaking change.

## Concurrency

- Parsing and per-file rules: process pool, one file per task. Trivially parallel.
- Graph construction: single-threaded per layer; layers that don't depend on each other
  (dependency graph vs call graph) run concurrently.
- Taint analysis: parallel per entry point, since paths are independent. Shared read-only graph.
- AI: bounded concurrency with per-provider rate limiting; never blocks the deterministic result.

## Incrementality

Everything keys off a content hash per file. On re-run, unchanged files reuse cached AST,
symbols and per-file findings. Interprocedural results are invalidated by transitive closure
over the call graph: change a function, invalidate every caller's paths. This is the mechanism
behind NFR-2 and behind `vigilloo review --diff`.

## Failure policy

A plugin that throws is disabled for the run, its failure recorded in the manifest, and the
scan continues. A parse error on one file degrades that file to "unparsed" and continues.
A partial scan that reports what it found and what it could not reach beats a clean exit code
that hides a crash. Every report states its own coverage.

## Extension points

Language, framework, scanner, reporter, AI provider, attack module - all plugins, all
discovered through entry points. See [11-plugin-sdk](../11-plugin-sdk/README.md).
