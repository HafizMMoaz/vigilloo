# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status: first vertical slice implemented

The spec in `docs/` is complete. `src/` is a working Python package: PHP parser, symbol
extraction, Laravel route table, call graph, kind-based interprocedural taint analysis, and SQL
injection findings with evidence paths. Everything beyond that slice is still spec only.

```bash
uv sync --all-extras
uv run pytest
uv run ruff format --check .
uv run ruff check
uv run mypy                # strict, configured over src/ in pyproject.toml
```

CI (`.github/workflows/ci.yml`) runs exactly those four checks on push to `main` and on every PR.

## Layout

**The target layout is specified in [23-dev-guide](docs/23-dev-guide/README.md) - follow it.**
`src/` grows into the subpackages it names (`cli/`, `parser/`, `graph/`, `analysis/`,
`security/`, `sdk/`, `plugins/php/`, `plugins/laravel/`, …). The current flat modules are the
first slice, not a different plan. `sdk/` is the only stability boundary; everything else is
internal and may be restructured freely. Do not introduce sibling top-level package directories.

**`src/` is the `vigilloo` package, not a directory containing it.** There is no
`src/vigilloo/`; `pyproject.toml` maps the directory onto the import name, so `src/cli.py` is
imported as `vigilloo.cli`. Two rules follow, and breaking either fails quietly:

1. **Imports inside `src/` are relative** - `from .models import Finding`, never
   `from vigilloo.models import Finding`. There is no `vigilloo/` on disk to import absolutely.
   Tests and external callers still use the absolute `vigilloo.` name.
2. **Register every new subpackage in `pyproject.toml`**, in both `package-dir` and `packages`.
   A renaming `package-dir` does not compose with `packages.find`, so nothing is auto-discovered.
   An unregistered subpackage still imports fine in the editable dev install and is silently
   missing from the wheel. CI builds the wheel and installs it into a clean environment for
   exactly this reason - do not remove that step.

This layout is the user's explicit decision. Do not "fix" it back to `src/vigilloo/`.

- `docs/00-…24-*/README.md` - the specification, one document per subsystem. Numbering is the
  reading order: vision → PRD → architecture → analysis pipeline → detection → interfaces → ops.
  **These are written specs, not stubs. Read the relevant one before designing anything.**
- `docs/plans/` - implementation plans. Working documents, not spec.
- `src/`, `tests/`, `scripts/` - the package, its tests, and dev utilities.
- `README.md` - repo front page. `docs/README.md` is the index into the spec.
- `TEMP/` - original brainstorm notes the specs were derived from. Historical; `docs/` supersedes
  them. `Vigilloo_Docs_Repo.zip` is a stale copy of the pre-expansion docs - ignore it. Gitignored,
  local only.

## What Vigilloo is

An AI-native application security platform. The differentiator is the **knowledge graph**: a
finding is not a line number and a severity, it is a traversal from an HTTP route through the
call graph to an unsanitized sink, with every step a real edge. If a change makes it harder to
produce or trust that path, it is the wrong change.

## v0.1 scope - decided

- **PHP 8.1+ / Laravel 9-11 only.** One language, one framework, done properly. Not a starting
  point to be widened opportunistically - breadth is v1.0+ per [24-roadmap](docs/24-roadmap/README.md).
- **No AI dependency.** The full pipeline works offline with no API key. AI arrives in v0.5.
- **Nothing intrusive.** Attack engine ships disabled.
- CLI binary is **`vigilloo`** (Latin *vigil*, watchman). Never `vigil` - that spelling appears
  only in the brand story.

## Architecture

Single Python 3.13+ process; a pipeline where each stage reads the previous stage's output from
the SQLite workspace. Full detail in [02-architecture](docs/02-architecture/README.md).

```
Detect → Parse → Enrich (Laravel adapter) → Graph → Analyse → [Reason] → Report
                                                                 ↑ optional
MCP server and (v2) desktop are clients over the same engines - never a second analysis path.
```

The layering rule that keeps this honest: **each subsystem knows only about the one below it.**
The parser has no Laravel awareness; the graph engine has no security awareness; the security
engine has no LLM awareness. Violations are the main architectural smell to watch for.

## Non-negotiable invariants

Breaking any of these is a design error, not a tradeoff:

1. **The AI engine cannot create or delete a finding.** It explains, ranks and patches
   deterministic findings. An LLM "false positive" verdict annotates a finding; it does not
   remove it. Deterministic results must be identical with AI on and off - this is asserted in CI.
2. **Every finding carries a complete evidence path.** No path, no finding.
3. **Node and finding IDs are content-derived and deterministic**, never autoincrement. Stable
   IDs are what make baselines, suppressions and incremental invalidation work. Findings also
   carry a location-independent `fingerprint` so they survive reformatting.
4. **Coverage is reported, never hidden.** Parse failures and unresolved call edges appear in
   every report. A clean result over a codebase 40% of which failed to parse is a lie.
5. **Analysed code is untrusted input** - never executed, never imported, and delimited as data
   (not instructions) when sent to an LLM.
6. **Offline is complete.** No feature outside the AI layer and advisory refresh may require
   network access.
7. **Rule IDs are permanent.** They ship in users' SARIF, baselines and `// vigilloo-ignore`
   comments. Renaming one un-suppresses findings in every codebase using it.
8. **Determinism.** Same input + same ruleset ⇒ byte-identical JSON output, AI excluded.

## Where the Laravel value concentrates

The rules that justify the whole graph are the framework-structural ones - they need the route
table, middleware stack, model config and policy map together, and no single-file scanner can
produce them: mass assignment via `$guarded = []`, IDOR from route-model binding with no policy,
`VerifyCsrfToken::$except` wildcards, `APP_DEBUG`/`APP_KEY` in production, `env()` outside
`config/`, validated-then-`$request->all()`.

Two details that decide precision, both in [06-taint-analysis](docs/06-taint-analysis/README.md):

- **Taint is kind-based, not boolean.** `e()` clears `html`, not `sql`. A boolean flag produces
  both false positives and false negatives.
- **`whereRaw('age > ?', [$age])` is safe; `whereRaw("age > $age")` is not.** Rules must check
  which argument taint reaches. Flagging every `*Raw` call is the noise that makes developers
  stop reading security reports.

## Docs are the spec

`docs/` is normative. A change to detection behaviour, the `Finding` schema, plugin interfaces
or the CLI surface updates its document in the same commit. When implementing, read the relevant
doc first - the specs contain decided details (schemas, resolution strategies, sink tables) that
are expensive to rediscover and easy to contradict.

## Conventions

- **No em dashes anywhere.** Docs, code comments, commit messages, chat. Use a hyphen (`-`).
  Box-drawing characters in ASCII diagrams are fine and unrelated.
- **Never add Claude as a co-author or collaborator** on any commit or PR. No
  `Co-Authored-By: Claude` trailer, no "Generated with Claude Code" footer. This overrides the
  default Claude Code commit guidance.

## Context

- Repo: `github.com/HafizMMoaz/vigilloo`, **private**. `gh` CLI is authenticated as `HafizMMoaz`.
  The old `vigilloo` GitHub org and its two repos were folded into this one and deleted.
- **Proprietary, not open source.** See `LICENSE`. The product ships as free and paid tiers, so
  never add an OSI licence header, an open-source badge, or a "contributions welcome" section.
- **Webisters** (`github.com/webisters`) is the user's own full-stack PHP framework, ~37 modular
  packages. It is a first-class adapter target scheduled for v0.5, not a third-party unknown.
  Its API surface is specified in `docs/08-framework-adapters`.
- No reserved PyPI package name yet.
