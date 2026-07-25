# Developer Guide

## Requirements

Python 3.13+, `uv` for dependency and environment management, git. No compiler needed -
Tree-sitter grammars ship as wheels.

## Setup

```bash
git clone <repo> && cd vigilloo
uv sync --all-extras          # includes dev dependencies
uv run vigilloo doctor        # verify the environment
uv run pytest                 # fast suite
```

## Repository layout

```text
src/vigilloo/
  cli/            Typer commands, Rich/Textual output
  workspace/      project root, config, run manifest
  parser/         Tree-sitter integration, symbols, imports
  graph/          node/edge model, store, NetworkX bridge, queries
  analysis/       CFG, data flow, call graph, taint engine
  security/       rule engine, built-in rules, findings
  ai/             providers, context assembly, validation gate
  rag/            corpus, chunking, LanceDB index, retrieval
  report/         reporters, templates, SARIF
  mcp/            MCP server
  sdk/            public plugin interfaces - the stability boundary
  plugins/
    php/          language plugin
    laravel/      framework adapter, rules, summaries
tests/
  unit/  fixtures/  corpus/  regression/  perf/
docs/             these documents
```

`sdk/` is the only package with a stability guarantee. Everything else is internal and may be
restructured freely - keeping that boundary explicit is what allows the internals to change
without breaking plugins.

## Standards

**Type hints everywhere.** `mypy --strict` on `src/`. In a codebase whose whole job is precise
reasoning about other people's types, untyped internals are indefensible.

**`Protocol` over inheritance** for plugin interfaces - structural typing means plugins need no
base class from core.

**Dataclasses for data**, frozen where the value should not mutate. Findings and graph nodes are
frozen; a rule that mutates a finding it did not create is a bug.

**No global state.** Everything reaches code through `Workspace` or `PluginContext`. Global
singletons make parallel scanning and testing painful in exactly the ways that matter here.

**Errors are values at plugin boundaries, exceptions internally.** A plugin raising must never
crash a scan ([11-plugin-sdk](../11-plugin-sdk/README.md)).

Formatting and linting: `ruff format`, `ruff check`. Both run in CI and in pre-commit.

## Adding a rule

1. Prefer YAML in `plugins/<x>/rules/` - declarative rules cannot crash a scan, cannot loop
   forever, and need no review of imperative logic.
2. Write the positive **and** negative fixture before the rule. Test-first is not a preference
   here: a rule written before its negative case reliably over-fires.
3. Choose a permanent rule ID. It ships in SARIF, in users' baselines, and in
   `// vigilloo-ignore` comments in their source. Renaming one un-suppresses findings in every
   codebase that used it.
4. Set severity from realistic impact, not from how clever the detection was.
5. Write the deterministic remediation text. The AI layer enriches it; it must be useful without.
6. Run the corpus suite and review every changed finding. A new rule that shifts unrelated
   results is a bug in the rule.

## Adding a framework adapter

Read [08-framework-adapters](../08-framework-adapters/README.md), implement `FrameworkAdapter`,
and if the interface does not fit - **change the interface, do not special-case the adapter**.
The interface exists to be framework-neutral, and the second adapter is what proves whether it is.

## Performance

Profile before optimising; `pytest-benchmark` guards the NFR targets. The three things that
actually matter, in order:

1. **Cache correctness.** Most scans are incremental. A cache that is wrong is worse than no
   cache; a cache that misses unnecessarily is the top cause of slow re-scans.
2. **Query patterns.** N+1 queries against SQLite dominate graph construction if unwatched.
   Batch node and edge inserts.
3. **Parallelism.** Parsing and per-entry-point taint analysis are embarrassingly parallel.
   Everything else is usually not worth the complexity.

Do not micro-optimise the parser. Tree-sitter is fast; time goes to graph construction and
interprocedural analysis.

## Security of Vigilloo itself

A security tool is a high-value target, and it runs on machines holding source code.

- **Analysed code is untrusted input.** Never `eval`, never import, never execute it. The
  analysis is entirely static, and that is a security property, not just an architectural one.
- **Analysed content is untrusted for LLMs too** - see the prompt injection section in
  [09-ai-engine](../09-ai-engine/README.md).
- **Path traversal in our own code.** A crafted `composer.json` autoload map must not make
  Vigilloo read or write outside the project root.
- **Zip/archive handling** - no automatic extraction of anything from a scanned project.
- **Redact before transmit.** Secret findings must never send the secret to an AI provider.
- **Dependency hygiene.** Pinned lockfile, `pip-audit` in CI. We do not get to skip our own advice.

## Commits and releases

Conventional commits; semver. The CLI and the SDK version independently - an SDK major bump
breaks plugins and must be deliberate. Every release records its ruleset hash so scan results
stay reproducible ([17-database](../17-database/README.md)).

## Documentation

`docs/` is the specification, not an afterthought. A change to detection behaviour, the finding
schema, the plugin interfaces or the CLI surface updates its doc in the same commit. These
documents are what future contributors and future Claude Code sessions read first, and a stale
spec is worse than a missing one.
