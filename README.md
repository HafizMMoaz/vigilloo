# Vigilloo

AI-native application security platform. A finding is not a line number and a severity - it is
a traversal from an HTTP route through the call graph to an unsanitized sink, with every step a
real edge.

Proprietary. See [LICENSE](LICENSE).

## Layout

| Path | What |
|------|------|
| [`docs/`](docs/README.md) | The specification. Normative - `00`…`24`, numbered in reading order. |
| [`CHANGELOG.md`](CHANGELOG.md) | Release record. Every rule ID added or removed is announced here. |
| `src/` | The analysis engine and the `vigilloo` CLI. This directory *is* the `vigilloo` package. |
| `tests/` | Test suite and Laravel fixture projects. |

`docs/` is the spec, not notes. A change to detection behaviour, the `Finding` schema, plugin
interfaces or the CLI surface updates its document in the same commit. The target layout for
`src/` is set out in [docs/23-dev-guide](docs/23-dev-guide/README.md).

## Status

v0.1, in progress. `vigilloo scan` parses a Laravel project, builds the graph, runs the taint
and structural rules, prints every finding with its complete evidence path and its coverage,
and records the scan in the SQLite store under `.vigilloo/`. Four rules ship today:
`php.sql-injection`, `php.xss`, `laravel.mass-assignment` and `laravel.missing-authorization`.

**Per-capability status lives in the v0.1 table in
[docs/24-roadmap](docs/24-roadmap/README.md)**, which is the one place it is recorded. Released
changes are in [CHANGELOG.md](CHANGELOG.md).

```
$ vigilloo scan tests/fixtures/laravel-minimal

Coverage: 16/16 files parsed (100.0%), 52/52 call sites resolved (100.0%)

CRITICAL - SQL Injection
  app/Repositories/OrderRepository.php:12 · CWE-89 · php.sql-injection

  1. api.php:7  entry    POST /orders/search -> OrderController::search
  2. OrderController.php:17  source  $sort = $request->input('sort')
  3. OrderController.php:19  flows   argument 0 into OrderRepository::search
  4. OrderRepository.php:12  sink    DB::table('orders')->orderByRaw("created_at {$sort}")

10 findings (1 critical, 9 high)
```

Coverage is printed on every scan, including when it is 100%. A clean result over a codebase
that half failed to parse is a lie, so the denominator is never hidden.

Scope for v0.1 is PHP 8.1+ / Laravel 9-11 only, with no AI dependency - the full pipeline runs
offline with no API key. See [docs/24-roadmap](docs/24-roadmap/README.md).

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff format --check .
uv run ruff check
uv run mypy
```
