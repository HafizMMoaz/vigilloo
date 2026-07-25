# Vigilloo

AI-native application security platform. A finding is not a line number and a severity - it is
a traversal from an HTTP route through the call graph to an unsanitized sink, with every step a
real edge.

Proprietary. See [LICENSE](LICENSE).

## Layout

| Path | What |
|------|------|
| [`docs/`](docs/README.md) | The specification. Normative - `00`…`24`, numbered in reading order. |
| `src/` | The analysis engine and the `vigilloo` CLI. This directory *is* the `vigilloo` package. |
| `tests/` | Test suite and Laravel fixture projects. |

`docs/` is the spec, not notes. A change to detection behaviour, the `Finding` schema, plugin
interfaces or the CLI surface updates its document in the same commit. The target layout for
`src/` is set out in [docs/23-dev-guide](docs/23-dev-guide/README.md).

## Status

v0.1, in progress. The first vertical slice is implemented: PHP parsing, symbol extraction,
Laravel route table, call graph, kind-based interprocedural taint analysis, and SQL injection
findings with complete evidence paths.

```
$ vigilloo scan tests/fixtures/laravel-minimal

CRITICAL - SQL Injection
  app/Repositories/OrderRepository.php:12 · CWE-89 · php.sql-injection

  1. api.php:7  entry    POST /orders/search -> OrderController::search
  2. OrderController.php:17  source  $sort = $request->input('sort')
  3. OrderController.php:19  flows   argument 0 into OrderRepository::search
  4. OrderRepository.php:12  sink    DB::table('orders')->orderByRaw("created_at {$sort}")
```

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
