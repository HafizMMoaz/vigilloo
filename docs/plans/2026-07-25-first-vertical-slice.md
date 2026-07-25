# First Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `vigilloo scan <laravel-app>` detects one SQL injection in a fixture Laravel app and prints the complete evidence path from HTTP route to unsanitized sink.

**Architecture:** A thin vertical cut through every layer of the specification: Tree-sitter parses PHP into an AST, a symbol extractor builds fully-qualified names, a Laravel route extractor finds entry points, a call graph resolves method calls through typed constructor-injected properties, and a taint engine walks from source to sink recording each step. The evidence path is the deliverable; a finding without a complete path is a failure.

**Tech Stack:** Python 3.13+, uv, tree-sitter + tree-sitter-php, Typer, Rich, pytest, ruff, mypy.

## Global Constraints

- Python 3.13+ only.
- **No em dashes (U+2014) or en dashes (U+2013) anywhere**: code, comments, docstrings, commit messages, output strings. Use a plain hyphen `-`.
- **Never add Claude as co-author or collaborator.** No `Co-Authored-By: Claude` trailer, no "Generated with Claude Code" footer on commits or PRs.
- Fully offline. No network calls in any code path in this slice.
- Deterministic: same input produces identical output. No iteration-order dependence, no timestamps in findings.
- Every finding carries a complete evidence path. No path, no finding.
- Type hints on all functions. `mypy --strict` passes on `src/`.
- Frozen dataclasses for all data models.
- Conventional commit messages (`feat:`, `test:`, `chore:`).

## Deliberately deferred to slice 2

Recorded here so they are visible decisions, not oversights. Each gets a `# ponytail:` comment at the relevant place in code.

| Deferred | Why it is safe to defer | When to add |
| --- | --- | --- |
| SQLite persistence (`docs/17-database`) | The graph is built in memory per run. Persistence buys incrementality, which this slice does not need to prove the path. | Slice 2, before any performance work |
| Control flow graph (`docs/05-data-flow-analysis`) | Taint walks statements linearly. Enough for straight-line controller code. | When a fixture needs branch-sensitive sanitizing |
| Taint kinds (`docs/06-taint-analysis`) | Slice 1 tracks only the `sql` kind, so a boolean per variable suffices. | Slice 2, when the second sink class (html) lands |
| Facade and container resolution (`docs/07-call-graph`) | The fixture uses constructor injection, the idiomatic Laravel path. | When a fixture uses `DB::` directly |
| Blade parsing | No XSS rule in this slice. | With the html taint kind |
| AI engine, RAG, SARIF, incremental scan | All downstream of a working path. | Per `docs/24-roadmap` |

## File Structure

```
src/vigilloo/
  __init__.py        version string
  models.py          Span, Symbol, Route, PathStep, Finding - all frozen dataclasses
  parser.py          Tree-sitter setup, parse file to tree, node helpers
  symbols.py         namespace/class/method/property extraction, FQN resolution
  laravel/
    __init__.py
    routes.py        Route::verb(...) extraction from routes/*.php
    vocabulary.py    Laravel taint sources and sinks
  graph.py           in-memory node/edge store, call resolution
  taint.py           intra- and interprocedural taint walk, path construction
  rules.py           rule definitions, finding assembly
  report.py          Rich terminal rendering of findings and evidence paths
  cli.py             Typer app, `scan` command
tests/
  fixtures/laravel-minimal/    the vulnerable + safe fixture app
  test_parser.py
  test_symbols.py
  test_routes.py
  test_graph.py
  test_taint.py
  test_scan.py                 end-to-end, including must_not_find
docs/plans/                    this plan
```

Files split by responsibility, not layer. `laravel/` is separated from core because the layering rule in `CLAUDE.md` says core must never import framework specifics.

---

### Task 1: Project scaffold and runnable CLI

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `README.md`
- Create: `src/vigilloo/__init__.py`, `src/vigilloo/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: nothing
- Produces: `vigilloo.__version__: str`, a Typer app `vigilloo.cli.app`, console script `vigilloo`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
from typer.testing import CliRunner

from vigilloo import __version__
from vigilloo.cli import app

runner = CliRunner()


def test_version_flag_prints_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo'`

- [ ] **Step 3: Write pyproject.toml**

```toml
[project]
name = "vigilloo"
version = "0.0.1"
description = "AI-native application security platform"
requires-python = ">=3.13"
dependencies = [
    "typer>=0.12",
    "rich>=13.7",
    "tree-sitter>=0.23",
    "tree-sitter-php>=0.23",
]

[project.scripts]
vigilloo = "vigilloo.cli:app"

[dependency-groups]
dev = ["pytest>=8.0", "mypy>=1.11", "ruff>=0.6"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/vigilloo"]

[tool.ruff]
line-length = 100
target-version = "py313"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[tool.mypy]
strict = true
files = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 4: Write the package files**

```python
# src/vigilloo/__init__.py
__version__ = "0.0.1"
```

```python
# src/vigilloo/cli.py
"""Command line interface for Vigilloo."""

import typer

from vigilloo import __version__

app = typer.Typer(
    name="vigilloo",
    help="AI-native application security platform.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vigilloo {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Vigilloo command line interface."""
```

```
# .gitignore
__pycache__/
*.py[cod]
.venv/
.pytest_cache/
.mypy_cache/
.ruff_cache/
dist/
.vigilloo/
.DS_Store
```

```markdown
<!-- README.md -->
# Vigilloo

AI-native application security platform. Specification lives in
[vigilloo/docs](https://github.com/vigilloo/docs).

## Development

```bash
uv sync
uv run pytest
uv run ruff check
uv run mypy
```
```

- [ ] **Step 5: Install and run test to verify it passes**

Run: `uv sync && uv run pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 6: Verify lint and types are clean**

Run: `uv run ruff check && uv run ruff format --check && uv run mypy`
Expected: all clean, no errors

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: project scaffold with runnable CLI"
```

---

### Task 2: Fixture Laravel app and grammar verification

The fixture is the specification of correct behaviour for every later task. It contains one vulnerable path and one safe path that must stay silent.

**Files:**
- Create: `tests/fixtures/laravel-minimal/composer.json`
- Create: `tests/fixtures/laravel-minimal/routes/api.php`
- Create: `tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php`
- Create: `tests/fixtures/laravel-minimal/app/Repositories/OrderRepository.php`
- Create: `scripts/dump_ast.py`

**Interfaces:**
- Consumes: nothing
- Produces: fixture path `tests/fixtures/laravel-minimal`, used by every later test

- [ ] **Step 1: Write the fixture composer.json**

```json
{
  "name": "vigilloo/fixture-laravel-minimal",
  "require": {
    "php": "^8.1",
    "laravel/framework": "^11.0"
  },
  "autoload": {
    "psr-4": {
      "App\\": "app/"
    }
  }
}
```

- [ ] **Step 2: Write the fixture routes file**

```php
<?php
// tests/fixtures/laravel-minimal/routes/api.php

use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;

Route::post('/orders/search', [OrderController::class, 'search']);
Route::get('/orders/recent', [OrderController::class, 'recent']);
```

- [ ] **Step 3: Write the fixture controller**

`search` is the vulnerable action. `recent` is the safe action and must never produce a finding.

```php
<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php

namespace App\Http\Controllers;

use App\Repositories\OrderRepository;
use Illuminate\Http\Request;

class OrderController
{
    public function __construct(private OrderRepository $orders)
    {
    }

    public function search(Request $request)
    {
        $sort = $request->input('sort');

        return $this->orders->search($sort);
    }

    public function recent(Request $request)
    {
        return $this->orders->recent();
    }
}
```

- [ ] **Step 4: Write the fixture repository**

```php
<?php
// tests/fixtures/laravel-minimal/app/Repositories/OrderRepository.php

namespace App\Repositories;

use Illuminate\Support\Facades\DB;

class OrderRepository
{
    public function search(string $sort)
    {
        return DB::table('orders')->orderByRaw("created_at {$sort}")->get();
    }

    public function recent()
    {
        return DB::table('orders')->orderBy('created_at', 'desc')->limit(10)->get();
    }
}
```

- [ ] **Step 5: Write the AST dump script**

The exact Tree-sitter node type names must be confirmed against the installed grammar rather than assumed. Every later task depends on these names being right.

```python
# scripts/dump_ast.py
"""Print the Tree-sitter s-expression for a PHP file.

Usage: uv run python scripts/dump_ast.py <path-to-php-file>
"""

import sys
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Parser


def main() -> None:
    language = Language(tree_sitter_php.language_php())
    parser = Parser(language)
    source = Path(sys.argv[1]).read_bytes()
    tree = parser.parse(source)
    print(tree.root_node)


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run the dump and record the real node names**

Run:
```bash
uv run python scripts/dump_ast.py tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php
uv run python scripts/dump_ast.py tests/fixtures/laravel-minimal/routes/api.php
```

Expected: an s-expression tree. Read it and confirm the node type names used in Tasks 4 to 9:

| Concept | Expected node type |
| --- | --- |
| namespace | `namespace_definition` |
| class | `class_declaration` |
| method | `method_declaration` |
| parameter list | `formal_parameters` |
| plain parameter | `simple_parameter` |
| promoted constructor parameter | `property_promotion_parameter` |
| `$x` | `variable_name` |
| `$a = $b` | `assignment_expression` |
| `$obj->m()` | `member_call_expression` |
| `Cls::m()` | `scoped_call_expression` |
| `"a {$b}"` | `encapsed_string` |
| call arguments | `arguments` / `argument` |

**If any name differs, use the real one and note the correction at the top of `src/vigilloo/parser.py`.** Do not proceed with a guessed name.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "test: add minimal Laravel fixture and AST dump script"
```

---

### Task 3: Core data models

**Files:**
- Create: `src/vigilloo/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `Span(file: Path, start_line: int, start_col: int, end_line: int, end_col: int)`
  - `Symbol(fqn: str, kind: str, span: Span, params: tuple[str, ...], param_types: tuple[str | None, ...])`
  - `Route(uri: str, verbs: tuple[str, ...], action_fqn: str, middleware: tuple[str, ...], span: Span)`
  - `PathStep(role: str, span: Span, snippet: str, note: str)`
  - `Finding(rule_id, severity, title, cwe, span, evidence_path)` with property `fingerprint: str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
from pathlib import Path

from vigilloo.models import Finding, PathStep, Span


def _span(line: int) -> Span:
    return Span(Path("a.php"), line, 0, line, 10)


def test_finding_requires_evidence_path():
    """A finding without a path is a bug, not a finding."""
    try:
        Finding(
            rule_id="php.sql-injection",
            severity="critical",
            title="SQL Injection",
            cwe=("CWE-89",),
            span=_span(42),
            evidence_path=(),
        )
    except ValueError as exc:
        assert "evidence path" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError for empty evidence path")


def test_fingerprint_is_stable_across_line_moves():
    """Fingerprints must survive reformatting so baselines keep working."""
    steps_a = (PathStep("source", _span(10), "$r->input('s')", ""),
               PathStep("sink", _span(42), "orderByRaw", ""))
    steps_b = (PathStep("source", _span(30), "$r->input('s')", ""),
               PathStep("sink", _span(62), "orderByRaw", ""))
    a = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(42), steps_a)
    b = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(62), steps_b)
    assert a.fingerprint == b.fingerprint
    assert a.id != b.id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.models'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/models.py
"""Core data models shared by every subsystem.

All models are frozen. A rule must never mutate a finding it did not create.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Span:
    """A byte range in a source file, as 1-indexed lines and 0-indexed columns."""

    file: Path
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __str__(self) -> str:
        return f"{self.file}:{self.start_line}"


@dataclass(frozen=True)
class Symbol:
    """A named declaration: class, method or function."""

    fqn: str
    kind: str
    span: Span
    params: tuple[str, ...] = ()
    param_types: tuple[str | None, ...] = ()


@dataclass(frozen=True)
class Route:
    """An HTTP entry point mapped to a controller action."""

    uri: str
    verbs: tuple[str, ...]
    action_fqn: str
    middleware: tuple[str, ...]
    span: Span


@dataclass(frozen=True)
class PathStep:
    """One step in a finding's evidence path.

    role is one of: source, propagator, sanitizer, sink, entry.
    """

    role: str
    span: Span
    snippet: str
    note: str = ""


@dataclass(frozen=True)
class Finding:
    """A security finding with a complete evidence path."""

    rule_id: str
    severity: str
    title: str
    cwe: tuple[str, ...]
    span: Span
    evidence_path: tuple[PathStep, ...]
    remediation: str = ""
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.evidence_path:
            raise ValueError(
                f"finding {self.rule_id} has an empty evidence path; "
                "a finding without a path is a bug in Vigilloo"
            )

    @property
    def id(self) -> str:
        """Exact identity. Changes when the code moves."""
        parts = [self.rule_id, str(self.span.file), str(self.span.start_line)]
        parts += [f"{s.role}:{s.span.start_line}" for s in self.evidence_path]
        return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]

    @property
    def fingerprint(self) -> str:
        """Identity that survives line movement within a file.

        The file path is deliberately part of the hash: the same pattern in
        two files is two distinct findings, and collapsing them would
        silently drop one.
        """
        parts = [self.rule_id, str(self.span.file)]
        parts += [f"{s.role}:{s.snippet.strip()}" for s in self.evidence_path]
        return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_models.py -v && uv run mypy`
Expected: PASS, mypy clean

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add core data models with stable finding fingerprints"
```

---

### Task 4: PHP parser

**Files:**
- Create: `src/vigilloo/parser.py`
- Test: `tests/test_parser.py`

**Interfaces:**
- Consumes: `vigilloo.models.Span`
- Produces:
  - `parse_php(path: Path) -> ParsedFile`
  - `ParsedFile(path: Path, source: bytes, tree: Tree, has_errors: bool)`
  - `node_text(node: Node, source: bytes) -> str`
  - `node_span(node: Node, path: Path) -> Span`
  - `walk(node: Node) -> Iterator[Node]`
  - `children_of_type(node: Node, type_name: str) -> list[Node]`
  - `find_all(node: Node, type_name: str) -> list[Node]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_parser.py
from pathlib import Path

from vigilloo.parser import find_all, node_text, parse_php

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_parses_controller_without_errors():
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    assert not parsed.has_errors
    assert parsed.tree.root_node.type == "program"


def test_finds_method_declarations():
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    methods = find_all(parsed.tree.root_node, "method_declaration")
    names = {
        node_text(m.child_by_field_name("name"), parsed.source)
        for m in methods
        if m.child_by_field_name("name") is not None
    }
    assert {"__construct", "search", "recent"} <= names


def test_broken_file_is_partial_not_fatal():
    """A parse error degrades one file, it never aborts a scan."""
    broken = Path("tests/fixtures/broken.php")
    broken.write_text("<?php class { function (")
    try:
        parsed = parse_php(broken)
        assert parsed.has_errors
    finally:
        broken.unlink()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_parser.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.parser'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/parser.py
"""Tree-sitter based PHP parsing.

Knows nothing about Laravel or about security. Framework meaning is added in
vigilloo.laravel, security meaning in vigilloo.rules.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Node, Parser, Tree

from vigilloo.models import Span


@cache
def _parser() -> Parser:
    # The text-mode `php` grammar handles `?>` ... `<?php` interleaving.
    return Parser(Language(tree_sitter_php.language_php()))


@dataclass(frozen=True)
class ParsedFile:
    path: Path
    source: bytes
    tree: Tree
    has_errors: bool


def parse_php(path: Path) -> ParsedFile:
    """Parse one PHP file. Never raises for malformed input."""
    source = path.read_bytes()
    tree = _parser().parse(source)
    return ParsedFile(
        path=path,
        source=source,
        tree=tree,
        has_errors=tree.root_node.has_error,
    )


def node_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def node_span(node: Node, path: Path) -> Span:
    start_row, start_col = node.start_point
    end_row, end_col = node.end_point
    return Span(path, start_row + 1, start_col, end_row + 1, end_col)


def walk(node: Node) -> Iterator[Node]:
    """Depth-first walk over every descendant, including node itself."""
    yield node
    for child in node.children:
        yield from walk(child)


def children_of_type(node: Node, type_name: str) -> list[Node]:
    return [c for c in node.children if c.type == type_name]


def find_all(node: Node, type_name: str) -> list[Node]:
    return [n for n in walk(node) if n.type == type_name]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_parser.py -v && uv run mypy`
Expected: PASS

If a node type name from Task 2 Step 6 differs from what this code assumes, fix it here and record the correction in the module docstring.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add error-tolerant PHP parser"
```

---

### Task 5: Symbol extraction

**Files:**
- Create: `src/vigilloo/symbols.py`
- Test: `tests/test_symbols.py`

**Interfaces:**
- Consumes: `vigilloo.parser.ParsedFile`, `vigilloo.models.Symbol`
- Produces:
  - `extract_symbols(parsed: ParsedFile) -> FileSymbols`
  - `FileSymbols(namespace: str, imports: dict[str, str], classes: dict[str, ClassInfo])`
  - `ClassInfo(fqn: str, span: Span, methods: dict[str, Symbol], properties: dict[str, str])` where `properties` maps property name to its resolved type FQN

`properties` is what makes constructor injection resolvable in Task 7, so promoted constructor parameters (`private OrderRepository $orders`) must be captured as properties.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_symbols.py
from pathlib import Path

from vigilloo.parser import parse_php
from vigilloo.symbols import extract_symbols

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_extracts_namespace_and_class_fqn():
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    syms = extract_symbols(parsed)
    assert syms.namespace == "App\\Http\\Controllers"
    assert "App\\Http\\Controllers\\OrderController" in syms.classes


def test_resolves_use_statements():
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    syms = extract_symbols(parsed)
    assert syms.imports["OrderRepository"] == "App\\Repositories\\OrderRepository"
    assert syms.imports["Request"] == "Illuminate\\Http\\Request"


def test_captures_promoted_constructor_property_type():
    """Constructor injection is how idiomatic Laravel obtains collaborators."""
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    syms = extract_symbols(parsed)
    cls = syms.classes["App\\Http\\Controllers\\OrderController"]
    assert cls.properties["orders"] == "App\\Repositories\\OrderRepository"


def test_captures_method_parameters_in_order():
    parsed = parse_php(FIXTURE / "app/Repositories/OrderRepository.php")
    syms = extract_symbols(parsed)
    cls = syms.classes["App\\Repositories\\OrderRepository"]
    assert cls.methods["search"].params == ("sort",)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_symbols.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.symbols'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/symbols.py
"""Symbol table construction: namespaces, imports, classes, methods, properties."""

from dataclasses import dataclass, field

from tree_sitter import Node

from vigilloo.models import Span, Symbol
from vigilloo.parser import ParsedFile, find_all, node_span, node_text


@dataclass(frozen=True)
class ClassInfo:
    fqn: str
    span: Span
    methods: dict[str, Symbol] = field(default_factory=dict)
    properties: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class FileSymbols:
    namespace: str
    imports: dict[str, str]
    classes: dict[str, ClassInfo]


def _namespace(root: Node, source: bytes) -> str:
    for node in find_all(root, "namespace_definition"):
        name = node.child_by_field_name("name")
        if name is not None:
            return node_text(name, source)
    return ""


def _imports(root: Node, source: bytes) -> dict[str, str]:
    """Map short name (or alias) to fully qualified name."""
    imports: dict[str, str] = {}
    for node in find_all(root, "namespace_use_declaration"):
        for clause in find_all(node, "namespace_use_clause"):
            text = node_text(clause, source).strip()
            if " as " in text:
                fqn, alias = (p.strip() for p in text.split(" as ", 1))
            else:
                fqn, alias = text, text.rsplit("\\", 1)[-1]
            imports[alias] = fqn.lstrip("\\")
    return imports


_BUILTIN_TYPES = frozenset({
    "string", "int", "float", "bool", "array", "object", "mixed",
    "callable", "iterable", "void", "null", "never", "false", "true",
    "self", "static", "parent",
})


def _resolve(type_name: str, namespace: str, imports: dict[str, str]) -> str:
    """Resolve a written type name to a fully qualified name.

    Builtins and union/intersection types are returned as written. Only class
    names get namespace resolution - prefixing a scalar would fabricate a type
    like App\\Repositories\\string and corrupt the property map.
    """
    type_name = type_name.strip().lstrip("?")
    if not type_name:
        return ""
    if "|" in type_name or "&" in type_name:
        return type_name
    if type_name.lower() in _BUILTIN_TYPES:
        return type_name.lower()
    if type_name.startswith("\\"):
        return type_name.lstrip("\\")
    head, _, rest = type_name.partition("\\")
    if head in imports:
        return f"{imports[head]}\\{rest}" if rest else imports[head]
    if namespace:
        return f"{namespace}\\{type_name}"
    return type_name


def _params(method: Node, source: bytes) -> tuple[tuple[str, ...], tuple[str | None, ...]]:
    names: list[str] = []
    types: list[str | None] = []
    params_node = method.child_by_field_name("parameters")
    if params_node is None:
        return (), ()
    for child in params_node.children:
        if child.type not in ("simple_parameter", "property_promotion_parameter"):
            continue
        name_node = child.child_by_field_name("name")
        type_node = child.child_by_field_name("type")
        names.append(node_text(name_node, source).lstrip("$"))
        types.append(node_text(type_node, source) if type_node is not None else None)
    return tuple(names), tuple(types)


def extract_symbols(parsed: ParsedFile) -> FileSymbols:
    root = parsed.tree.root_node
    source = parsed.source
    namespace = _namespace(root, source)
    imports = _imports(root, source)
    classes: dict[str, ClassInfo] = {}

    for cls in find_all(root, "class_declaration"):
        name_node = cls.child_by_field_name("name")
        if name_node is None:
            continue
        short = node_text(name_node, source)
        fqn = f"{namespace}\\{short}" if namespace else short
        info = ClassInfo(fqn=fqn, span=node_span(cls, parsed.path))

        for method in find_all(cls, "method_declaration"):
            m_name_node = method.child_by_field_name("name")
            if m_name_node is None:
                continue
            m_name = node_text(m_name_node, source)
            names, types = _params(method, source)
            info.methods[m_name] = Symbol(
                fqn=f"{fqn}::{m_name}",
                kind="method",
                span=node_span(method, parsed.path),
                params=names,
                param_types=tuple(
                    _resolve(t, namespace, imports) if t else None for t in types
                ),
            )
            # Promoted constructor parameters become properties. This is how
            # idiomatic Laravel injects collaborators, and it is what makes
            # $this->orders->search() resolvable in the call graph.
            params_node = method.child_by_field_name("parameters")
            if params_node is not None:
                for promoted in find_all(params_node, "property_promotion_parameter"):
                    p_name = node_text(promoted.child_by_field_name("name"), source).lstrip("$")
                    p_type = node_text(promoted.child_by_field_name("type"), source)
                    if p_name and p_type:
                        info.properties[p_name] = _resolve(p_type, namespace, imports)

        # Explicitly declared typed properties.
        for prop in find_all(cls, "property_declaration"):
            type_node = prop.child_by_field_name("type")
            for element in find_all(prop, "property_element"):
                p_name = node_text(element, source).split("=")[0].strip().lstrip("$")
                if p_name and type_node is not None:
                    info.properties[p_name] = _resolve(
                        node_text(type_node, source), namespace, imports
                    )

        classes[fqn] = info

    return FileSymbols(namespace=namespace, imports=imports, classes=classes)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_symbols.py -v && uv run mypy`
Expected: PASS

If `property_promotion_parameter` or `property_element` do not exist in the installed grammar, use the real names found in Task 2 Step 6.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: extract namespaces, imports, classes and injected properties"
```

---

### Task 6: Laravel route extraction

**Files:**
- Create: `src/vigilloo/laravel/__init__.py`, `src/vigilloo/laravel/routes.py`
- Test: `tests/test_routes.py`

**Interfaces:**
- Consumes: `vigilloo.parser`, `vigilloo.symbols`, `vigilloo.models.Route`
- Produces: `extract_routes(parsed: ParsedFile, symbols: FileSymbols) -> list[Route]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_routes.py
from pathlib import Path

from vigilloo.laravel.routes import extract_routes
from vigilloo.parser import parse_php
from vigilloo.symbols import extract_symbols

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_extracts_routes_with_resolved_action():
    parsed = parse_php(FIXTURE / "routes/api.php")
    routes = extract_routes(parsed, extract_symbols(parsed))
    by_uri = {r.uri: r for r in routes}

    assert set(by_uri) == {"/orders/search", "/orders/recent"}
    search = by_uri["/orders/search"]
    assert search.verbs == ("POST",)
    assert search.action_fqn == "App\\Http\\Controllers\\OrderController::search"
    assert search.span.start_line == 7


def test_routes_are_returned_in_deterministic_order():
    parsed = parse_php(FIXTURE / "routes/api.php")
    symbols = extract_symbols(parsed)
    assert extract_routes(parsed, symbols) == extract_routes(parsed, symbols)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_routes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.laravel'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/laravel/__init__.py
"""Laravel framework adapter."""
```

```python
# src/vigilloo/laravel/routes.py
"""Extract the Laravel route table, the application's attack surface inventory."""

from tree_sitter import Node

from vigilloo.models import Route
from vigilloo.parser import ParsedFile, find_all, node_span, node_text
from vigilloo.symbols import FileSymbols

# Route::get/post/... verb methods and the verbs they register.
_VERB_METHODS: dict[str, tuple[str, ...]] = {
    "get": ("GET", "HEAD"),
    "post": ("POST",),
    "put": ("PUT",),
    "patch": ("PATCH",),
    "delete": ("DELETE",),
    "options": ("OPTIONS",),
    "any": ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
}


def _string_literal(node: Node, source: bytes) -> str:
    return node_text(node, source).strip("'\"")


def _action_fqn(node: Node, source: bytes, symbols: FileSymbols) -> str:
    """Resolve [Controller::class, 'method'] or 'Controller@method' to an FQN."""
    text = node_text(node, source)

    if "::class" in text:
        short = text.split("::class")[0].strip().lstrip("[").strip()
        method = text.rsplit(",", 1)[-1].strip().rstrip("]").strip("'\" ")
        cls = symbols.imports.get(short, short)
        return f"{cls}::{method}"

    literal = text.strip("'\"")
    if "@" in literal:
        short, method = literal.split("@", 1)
        return f"{symbols.imports.get(short, short)}::{method}"

    return ""


def extract_routes(parsed: ParsedFile, symbols: FileSymbols) -> list[Route]:
    """Find Route::verb(uri, action) calls.

    ponytail: no group/prefix/resource expansion yet. The fixture registers flat
    routes. Add expansion when a fixture needs it - see docs 08-framework-adapters.
    """
    routes: list[Route] = []
    source = parsed.source

    for call in find_all(parsed.tree.root_node, "scoped_call_expression"):
        scope = node_text(call.child_by_field_name("scope"), source)
        if scope.rsplit("\\", 1)[-1] != "Route":
            continue

        method = node_text(call.child_by_field_name("name"), source)
        verbs = _VERB_METHODS.get(method)
        if verbs is None:
            continue

        args_node = call.child_by_field_name("arguments")
        if args_node is None:
            continue
        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
        if len(args) < 2:
            continue

        routes.append(
            Route(
                uri=_string_literal(args[0], source),
                verbs=verbs,
                action_fqn=_action_fqn(args[1], source, symbols),
                middleware=(),
                span=node_span(call, parsed.path),
            )
        )

    return sorted(routes, key=lambda r: (r.span.start_line, r.uri))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_routes.py -v && uv run mypy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: extract Laravel route table with resolved controller actions"
```

---

### Task 7: Project loading and call resolution

**Files:**
- Create: `src/vigilloo/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `vigilloo.parser`, `vigilloo.symbols`, `vigilloo.laravel.routes`
- Produces:
  - `load_project(root: Path) -> Project`
  - `Project(root, files: dict[Path, ParsedFile], symbols: dict[Path, FileSymbols], classes: dict[str, ClassInfo], routes: list[Route], failed: list[Path])`
  - `Project.method(fqn: str) -> Symbol | None`
  - `Project.class_of(fqn: str) -> ClassInfo | None`
  - `Project.resolve_property_type(class_fqn: str, prop: str) -> str | None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph.py
from pathlib import Path

from vigilloo.graph import load_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_loads_all_php_files_and_routes():
    project = load_project(FIXTURE)
    assert len(project.routes) == 2
    assert not project.failed
    assert "App\\Http\\Controllers\\OrderController" in project.classes
    assert "App\\Repositories\\OrderRepository" in project.classes


def test_resolves_injected_property_to_class():
    """$this->orders must resolve to OrderRepository for the call graph."""
    project = load_project(FIXTURE)
    resolved = project.resolve_property_type(
        "App\\Http\\Controllers\\OrderController", "orders"
    )
    assert resolved == "App\\Repositories\\OrderRepository"


def test_method_lookup_by_fqn():
    project = load_project(FIXTURE)
    method = project.method("App\\Repositories\\OrderRepository::search")
    assert method is not None
    assert method.params == ("sort",)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.graph'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/graph.py
"""In-memory project graph: files, symbols, classes and routes.

ponytail: in-memory only, rebuilt per run. SQLite persistence buys
incrementality, which this slice does not need - see docs 17-database.
"""

from dataclasses import dataclass, field
from pathlib import Path

from vigilloo.laravel.routes import extract_routes
from vigilloo.models import Route, Symbol
from vigilloo.parser import ParsedFile, parse_php
from vigilloo.symbols import ClassInfo, FileSymbols, extract_symbols

_EXCLUDED_DIRS = {"vendor", "node_modules", "storage", "bootstrap", ".git"}


@dataclass(frozen=True)
class Project:
    root: Path
    files: dict[Path, ParsedFile] = field(default_factory=dict)
    symbols: dict[Path, FileSymbols] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)
    failed: list[Path] = field(default_factory=list)

    def class_of(self, fqn: str) -> ClassInfo | None:
        return self.classes.get(fqn)

    def method(self, fqn: str) -> Symbol | None:
        class_fqn, _, method_name = fqn.rpartition("::")
        info = self.classes.get(class_fqn)
        return info.methods.get(method_name) if info else None

    def resolve_property_type(self, class_fqn: str, prop: str) -> str | None:
        info = self.classes.get(class_fqn)
        return info.properties.get(prop) if info else None

    def file_of_method(self, fqn: str) -> ParsedFile | None:
        method = self.method(fqn)
        return self.files.get(method.span.file) if method else None


def _php_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
    ]
    return sorted(found)  # sorted for determinism


def load_project(root: Path) -> Project:
    project = Project(root=root)

    for path in _php_files(root):
        try:
            parsed = parse_php(path)
        except OSError:
            project.failed.append(path)
            continue

        project.files[path] = parsed
        syms = extract_symbols(parsed)
        project.symbols[path] = syms
        project.classes.update(syms.classes)

        if path.parent.name == "routes":
            project.routes.extend(extract_routes(parsed, syms))

    project.routes.sort(key=lambda r: (str(r.span.file), r.span.start_line))
    return project
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_graph.py -v && uv run mypy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: load project into an in-memory graph with call resolution"
```

---

### Task 8: Laravel taint vocabulary

**Files:**
- Create: `src/vigilloo/laravel/vocabulary.py`
- Test: `tests/test_vocabulary.py`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `SOURCE_METHODS: frozenset[str]` - Request methods returning attacker-controlled data
  - `SQL_SINKS: dict[str, int]` - sink method name to the argument index that is dangerous
  - `SQL_SANITIZERS: frozenset[str]`
  - `is_source(method: str) -> bool`
  - `sink_arg_index(method: str) -> int | None`

`SQL_SINKS` maps to an argument index because `whereRaw('age > ?', [$age])` is safe while `whereRaw("age > $age")` is not. Flagging every raw call is the noise that makes developers stop reading reports.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_vocabulary.py
from vigilloo.laravel.vocabulary import is_source, sink_arg_index


def test_request_input_is_a_source():
    assert is_source("input")
    assert is_source("query")
    assert is_source("all")
    assert not is_source("validated")


def test_raw_sinks_declare_the_dangerous_argument():
    """whereRaw('age > ?', [$age]) is safe; only argument 0 is a sink."""
    assert sink_arg_index("orderByRaw") == 0
    assert sink_arg_index("whereRaw") == 0
    assert sink_arg_index("orderBy") is None
    assert sink_arg_index("where") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_vocabulary.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/laravel/vocabulary.py
"""Laravel and PHP taint vocabulary.

The canonical reference is docs/06-taint-analysis in the vigilloo/docs repo.
This module carries the subset needed for the SQL taint kind.
"""

# Illuminate\Http\Request methods returning attacker-controlled data.
SOURCE_METHODS: frozenset[str] = frozenset(
    {
        "input", "get", "query", "post", "json", "all", "only", "except",
        "string", "header", "cookie", "segment", "bearerToken", "userAgent",
        "url", "fullUrl", "ip",
    }
)

# Sink method name -> index of the argument that reaches the SQL parser.
# The *Raw builders accept bindings in argument 1, which are safe, so only
# argument 0 is dangerous.
SQL_SINKS: dict[str, int] = {
    "orderByRaw": 0,
    "whereRaw": 0,
    "orWhereRaw": 0,
    "havingRaw": 0,
    "groupByRaw": 0,
    "selectRaw": 0,
    "fromRaw": 0,
    "raw": 0,
    "statement": 0,
    "unprepared": 0,
    "select": 0,
}

SQL_SANITIZERS: frozenset[str] = frozenset({"intval", "e", "escapeshellarg"})


def is_source(method: str) -> bool:
    return method in SOURCE_METHODS


def sink_arg_index(method: str) -> int | None:
    return SQL_SINKS.get(method)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_vocabulary.py -v && uv run mypy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add Laravel SQL taint vocabulary with per-argument sinks"
```

---

### Task 9: Taint engine

The core of the slice. Walks from each route's action, tracks tainted variables, follows calls into other methods, and records every step.

**Files:**
- Create: `src/vigilloo/taint.py`
- Test: `tests/test_taint.py`

**Interfaces:**
- Consumes: `vigilloo.graph.Project`, `vigilloo.laravel.vocabulary`, `vigilloo.models.PathStep`
- Produces: `find_taint_paths(project: Project, max_depth: int = 5) -> list[list[PathStep]]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_taint.py
from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.taint import find_taint_paths

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_finds_the_interprocedural_path_to_the_sink():
    paths = find_taint_paths(load_project(FIXTURE))
    assert len(paths) == 1

    roles = [step.role for step in paths[0]]
    assert roles == ["entry", "source", "propagator", "sink"]

    entry, source, propagator, sink = paths[0]
    assert "/orders/search" in entry.snippet
    assert "input" in source.snippet
    assert source.span.start_line == 17
    assert propagator.span.start_line == 19
    assert "orderByRaw" in sink.snippet
    assert sink.span.file.name == "OrderRepository.php"
    assert sink.span.start_line == 12


def test_safe_action_produces_no_path():
    """The recent() action uses a bound orderBy and must stay silent."""
    paths = find_taint_paths(load_project(FIXTURE))
    assert all("recent" not in step.snippet for path in paths for step in path)


def test_paths_are_deterministic():
    project = load_project(FIXTURE)
    assert find_taint_paths(project) == find_taint_paths(project)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_taint.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.taint'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/taint.py
"""Taint propagation from route entry points to SQL sinks.

ponytail: statement-order walk, no CFG and no branch sensitivity. Straight-line
controller code is the common case; add a CFG when a fixture needs a sanitizer
applied on only one branch - see docs 05-data-flow-analysis.

ponytail: tracks only the `sql` taint kind as a boolean. The kind set from
docs 06-taint-analysis lands with the second sink class.
"""

from tree_sitter import Node

from vigilloo.graph import Project
from vigilloo.laravel.vocabulary import is_source, sink_arg_index
from vigilloo.models import PathStep
from vigilloo.parser import ParsedFile, find_all, node_span, node_text


def _var_name(node: Node, source: bytes) -> str:
    return node_text(node, source).lstrip("$")


def _referenced_vars(node: Node, source: bytes) -> set[str]:
    """Every variable read anywhere inside this expression."""
    return {_var_name(v, source) for v in find_all(node, "variable_name")}


def _call_parts(call: Node, source: bytes) -> tuple[str, str, list[Node]]:
    """Return (receiver text, method name, argument nodes) for a call node."""
    obj = node_text(call.child_by_field_name("object"), source)
    name = node_text(call.child_by_field_name("name"), source)
    args_node = call.child_by_field_name("arguments")
    args: list[Node] = []
    if args_node is not None:
        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
    return obj, name, args


def _method_body(project: Project, fqn: str) -> tuple[Node, ParsedFile] | None:
    symbol = project.method(fqn)
    if symbol is None:
        return None
    parsed = project.files.get(symbol.span.file)
    if parsed is None:
        return None
    for method in find_all(parsed.tree.root_node, "method_declaration"):
        span = node_span(method, parsed.path)
        if span.start_line == symbol.span.start_line:
            return method, parsed
    return None


def _walk_method(
    project: Project,
    fqn: str,
    tainted: set[str],
    prefix: list[PathStep],
    depth: int,
    max_depth: int,
) -> list[list[PathStep]]:
    """Walk one method body, returning every completed source-to-sink path."""
    if depth > max_depth:
        return []
    found = _method_body(project, fqn)
    if found is None:
        return []
    method_node, parsed = found
    source = parsed.source
    class_fqn = fqn.rpartition("::")[0]
    local = set(tainted)
    paths: list[list[PathStep]] = []

    for stmt in find_all(method_node, "expression_statement"):
        # 1. Assignment from a Request source, or from an already tainted value.
        for assign in find_all(stmt, "assignment_expression"):
            left = assign.child_by_field_name("left")
            right = assign.child_by_field_name("right")
            if left is None or right is None:
                continue
            target = _var_name(left, source)

            calls = find_all(right, "member_call_expression")
            if any(is_source(node_text(c.child_by_field_name("name"), source)) for c in calls):
                local.add(target)
                prefix = prefix + [
                    PathStep(
                        role="source",
                        span=node_span(assign, parsed.path),
                        snippet=node_text(assign, source).strip(),
                        note="attacker-controlled request data",
                    )
                ]
                continue

            if _referenced_vars(right, source) & local:
                local.add(target)

        # 2. Calls: either a sink, or a step deeper into another method.
        for call in find_all(stmt, "member_call_expression"):
            obj, name, args = _call_parts(call, source)

            index = sink_arg_index(name)
            if index is not None and index < len(args):
                if _referenced_vars(args[index], source) & local:
                    paths.append(
                        prefix
                        + [
                            PathStep(
                                role="sink",
                                span=node_span(call, parsed.path),
                                snippet=node_text(call, source).strip(),
                                note="unparameterised SQL fragment",
                            )
                        ]
                    )
                continue

            # $this->prop->method($tainted) - follow into the callee.
            if not obj.startswith("$this->"):
                continue
            prop = obj.removeprefix("$this->")
            target_class = project.resolve_property_type(class_fqn, prop)
            if target_class is None:
                continue
            callee_fqn = f"{target_class}::{name}"
            callee = project.method(callee_fqn)
            if callee is None:
                continue

            passed = {
                i for i, arg in enumerate(args) if _referenced_vars(arg, source) & local
            }
            if not passed:
                continue

            callee_tainted = {
                callee.params[i] for i in passed if i < len(callee.params)
            }
            if not callee_tainted:
                continue

            step = PathStep(
                role="propagator",
                span=node_span(call, parsed.path),
                snippet=node_text(call, source).strip(),
                note=f"argument {min(passed)} into {callee_fqn}",
            )
            paths.extend(
                _walk_method(
                    project, callee_fqn, callee_tainted,
                    prefix + [step], depth + 1, max_depth,
                )
            )

    return paths


def find_taint_paths(project: Project, max_depth: int = 5) -> list[list[PathStep]]:
    """Every source-to-sink path reachable from a route entry point."""
    paths: list[list[PathStep]] = []

    for route in project.routes:
        if not route.action_fqn:
            continue
        entry = PathStep(
            role="entry",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri} -> {route.action_fqn}",
            note="HTTP entry point",
        )
        paths.extend(
            _walk_method(project, route.action_fqn, set(), [entry], 0, max_depth)
        )

    return sorted(paths, key=lambda p: (str(p[-1].span.file), p[-1].span.start_line))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_taint.py -v && uv run mypy`
Expected: PASS

If the assertions on line numbers fail, correct the expected values to match the fixture rather than changing the fixture.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add interprocedural taint engine with evidence paths"
```

---

### Task 10: Rule and finding assembly

**Files:**
- Create: `src/vigilloo/rules.py`
- Test: `tests/test_rules.py`

**Interfaces:**
- Consumes: `vigilloo.taint.find_taint_paths`, `vigilloo.models.Finding`
- Produces: `scan_project(project: Project) -> list[Finding]`, `SQL_INJECTION: Rule`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_rules.py
from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_produces_one_critical_sql_injection_finding():
    findings = scan_project(load_project(FIXTURE))
    assert len(findings) == 1

    finding = findings[0]
    assert finding.rule_id == "php.sql-injection"
    assert finding.severity == "critical"
    assert finding.cwe == ("CWE-89",)
    assert finding.span.file.name == "OrderRepository.php"
    assert len(finding.evidence_path) == 4
    assert finding.remediation


def test_findings_are_stable_across_runs():
    a = scan_project(load_project(FIXTURE))
    b = scan_project(load_project(FIXTURE))
    assert [f.id for f in a] == [f.id for f in b]
    assert [f.fingerprint for f in a] == [f.fingerprint for f in b]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_rules.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vigilloo.rules'`

- [ ] **Step 3: Write the implementation**

```python
# src/vigilloo/rules.py
"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

from dataclasses import dataclass

from vigilloo.graph import Project
from vigilloo.models import Finding
from vigilloo.taint import find_taint_paths


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    remediation: str


SQL_INJECTION = Rule(
    id="php.sql-injection",
    title="SQL Injection",
    severity="critical",
    cwe=("CWE-89",),
    owasp=("A03:2021",),
    remediation=(
        "Pass user input as a query binding rather than interpolating it into "
        "the SQL string, or validate it against an allowlist. For an ORDER BY "
        "direction: $dir = $sort === 'asc' ? 'asc' : 'desc';"
    ),
)


def scan_project(project: Project) -> list[Finding]:
    """Run every rule over the project graph."""
    findings = [
        Finding(
            rule_id=SQL_INJECTION.id,
            severity=SQL_INJECTION.severity,
            title=SQL_INJECTION.title,
            cwe=SQL_INJECTION.cwe,
            span=path[-1].span,
            evidence_path=tuple(path),
            remediation=SQL_INJECTION.remediation,
        )
        for path in find_taint_paths(project)
    ]
    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_rules.py -v && uv run mypy`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: assemble SQL injection findings from taint paths"
```

---

### Task 11: Terminal report and the scan command

Closes the loop. After this task `vigilloo scan` produces the output in the goal.

**Files:**
- Create: `src/vigilloo/report.py`
- Modify: `src/vigilloo/cli.py`
- Test: `tests/test_scan.py`

**Interfaces:**
- Consumes: `vigilloo.rules.scan_project`, `vigilloo.models.Finding`
- Produces: `render(findings: list[Finding], console: Console) -> None`, CLI command `scan`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scan.py
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_scan_reports_the_finding_with_its_full_path():
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    out = result.stdout

    assert "SQL Injection" in out
    assert "CWE-89" in out
    assert "OrderRepository.php" in out
    assert "/orders/search" in out
    assert "orderByRaw" in out
    assert "1 finding" in out


def test_scan_exit_code_is_one_when_findings_exist():
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    assert result.exit_code == 1


def test_scan_of_clean_project_exits_zero(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Empty.php").write_text("<?php\nclass Empty_ {}\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings" in result.stdout


# The two dash characters below are the values under test. This file is the
# single sanctioned exception to the project-wide no-dash rule; they must not
# be replaced with hyphens or the assertion becomes meaningless.
def test_no_em_dashes_in_output():
    """Project convention: hyphens only."""
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    assert "—" not in result.stdout
    assert "–" not in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_scan.py -v`
Expected: FAIL, no `scan` command registered

- [ ] **Step 3: Write the report renderer**

```python
# src/vigilloo/report.py
"""Terminal rendering of findings.

The evidence path is the product. A severity label and a line number is what
every other scanner already prints.
"""

from rich.console import Console

from vigilloo.models import Finding

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_ROLE_LABEL = {
    "entry": "entry",
    "source": "source",
    "propagator": "flows",
    "sanitizer": "cleaned",
    "sink": "sink",
}


def render(findings: list[Finding], console: Console) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity, "white")
        console.print()
        console.print(
            f"[{style}]{finding.severity.upper()}[/{style}] - {finding.title}"
        )
        console.print(
            f"  [dim]{finding.span.file}:{finding.span.start_line} · "
            f"{' '.join(finding.cwe)} · {finding.rule_id}[/dim]"
        )
        console.print()

        for number, step in enumerate(finding.evidence_path, start=1):
            label = _ROLE_LABEL.get(step.role, step.role)
            console.print(
                f"  [dim]{number}.[/dim] {step.span.file.name}:{step.span.start_line}"
                f"  [bold]{label}[/bold]"
            )
            console.print(f"     [white]{step.snippet}[/white]")
            if step.note:
                console.print(f"     [dim]{step.note}[/dim]")

        console.print()
        console.print(f"  [bold]Fix:[/bold] {finding.remediation}")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
    plural = "s" if len(findings) != 1 else ""
    console.print()
    console.print(f"[bold]{len(findings)} finding{plural}[/bold] ({breakdown})")
```

- [ ] **Step 4: Add the scan command**

Add these imports and the command to `src/vigilloo/cli.py`:

```python
from pathlib import Path

from rich.console import Console

from vigilloo.graph import load_project
from vigilloo.report import render
from vigilloo.rules import scan_project


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Project root to scan."),
) -> None:
    """Scan a Laravel project for security findings."""
    console = Console()
    project = load_project(path)

    if project.failed:
        console.print(
            f"[yellow]{len(project.failed)} file(s) could not be read.[/yellow]"
        )

    findings = scan_project(project)
    render(findings, console)
    raise typer.Exit(1 if findings else 0)
```

- [ ] **Step 5: Run the full test suite**

Run: `uv run pytest -v && uv run mypy && uv run ruff check`
Expected: all tests pass, mypy clean, ruff clean

- [ ] **Step 6: Run it for real and confirm the output**

Run: `uv run vigilloo scan tests/fixtures/laravel-minimal`

Expected output shape:

```
CRITICAL - SQL Injection
  tests/fixtures/laravel-minimal/app/Repositories/OrderRepository.php:12 · CWE-89 · php.sql-injection

  1. api.php:7  entry
     POST /orders/search -> App\Http\Controllers\OrderController::search
  2. OrderController.php:17  source
     $sort = $request->input('sort')
  3. OrderController.php:19  flows
     $this->orders->search($sort)
  4. OrderRepository.php:12  sink
     ->orderByRaw("created_at {$sort}")

  Fix: Pass user input as a query binding ...

1 finding (1 critical)
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add scan command with evidence path output"
```

---

## Self-review notes

**Spec coverage.** This slice implements a thin cut of `docs/03-parser` (Tasks 4, 5), `docs/07-call-graph` (Task 7, typed-property resolution only), `docs/08-framework-adapters` (Tasks 6, 8, route and vocabulary extraction only), `docs/06-taint-analysis` (Tasks 8, 9, the `sql` kind only), `docs/13-security-engine` (Task 10, one rule), `docs/16-reporting` (Task 11, terminal only) and `docs/19-cli` (Task 11, `scan` only). Everything else in the specification is out of scope by design and listed in the deferral table above.

**Verification gates.** Every task runs `mypy` and the tests. Task 11 runs the whole suite plus a real invocation. Determinism is asserted in Tasks 6, 9 and 10. The `must_not_find` case, which matters as much as the positive case, is asserted in Task 9 (`test_safe_action_produces_no_path`) and implicitly in Task 10 (exactly one finding).

**Known risk.** Task 2 Step 6 exists because Tree-sitter node type names are asserted from documentation rather than from a running grammar. If any name differs, Tasks 4 to 9 need the real name substituted. This is why the grammar dump comes before any extractor is written.
