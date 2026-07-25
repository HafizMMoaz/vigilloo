# Slice 2 Implementation Plan: Kind-Based Taint and XSS Through Blade

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `vigilloo scan` reports a reflected XSS finding whose evidence path runs from an HTTP route through a controller, across a `view()` call, into a `.blade.php` template, and stops at a raw echo, while the same value rendered through `{{ }}` produces no finding.

**Architecture:** Taint marks become kind sets rather than booleans, and a recursive expression evaluator replaces flat variable matching so sanitizers can subtract the kinds they genuinely clear. Blade templates are rewritten line-for-line into PHP, with `{{ }}` becoming a real `e()` call, so auto-escaping falls out of ordinary sanitizer handling rather than needing a special case.

**Tech Stack:** Python 3.13+, uv, tree-sitter + tree-sitter-php, Typer, Rich, pytest, ruff, mypy.

**Design document:** [2026-07-26-slice-2-design.md](2026-07-26-slice-2-design.md). Where this plan and that design disagree, the design wins.

## Global Constraints

- **No em dashes anywhere.** Docs, code, comments, commit messages. Use a hyphen (`-`). The sole exception is `tests/test_scan.py`, where two dash characters are the values under test.
- **Never add Claude as a co-author.** No `Co-Authored-By` trailer, no generated-with footer.
- Every finding carries a complete evidence path. No path, no finding.
- Type hints on all functions. `mypy --strict` passes. Configured over `src/` in `pyproject.toml`.
- Frozen dataclasses for all data models, except `WalkStats`.
- Conventional commit messages (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`).
- Rule IDs are permanent. `php.xss` is fixed the moment it is written.
- Deferred shortcuts get a `# ponytail:` comment naming the ceiling and the upgrade path.
- `src/` **is** the `vigilloo` package. Imports inside `src/` are relative (`from .models import ...`). Any new subpackage must be registered in both `package-dir` and `packages` in `pyproject.toml`. This slice adds no new subpackage, only modules inside `src/laravel/`, which is already registered.
- All commands run from the repo root: `uv run pytest`, `uv run ruff check`, `uv run ruff format --check .`, `uv run mypy`.

## Verified grammar facts

These were checked against the real tree-sitter-php grammar before this plan was written. Do not guess alternatives; if one turns out wrong, correct it and note the correction at the top of `src/taint.py`.

| Construct | Node type | Fields |
| --- | --- | --- |
| `e($x)`, `intval($x)`, `view(...)`, `compact(...)` | `function_call_expression` | `function`, `arguments` |
| `(int)$x` | `cast_expression` | `type` (a `cast_type` node whose text is `int`, without parentheses), `value` |
| `$o->m($a)` | `member_call_expression` | `name`, `object`, `arguments` |
| `echo $x;` | `echo_statement` | none; the expression is a plain child |
| `['k' => $v]` | `array_creation_expression` containing `array_element_initializer` | none; key and value are the first and second **named** children |
| `'single'` | `string` | none; value is in a `string_content` named child |
| `"double"` | `encapsed_string` | none; value is in a `string_content` named child |

Because single and double quoted literals are different node types, read a literal's value by finding its first `string_content` descendant rather than by matching the node type.

The text-mode grammar (`tree_sitter_php.language_php()`, already used by `src/parser.py`) parses inline `<?php ... ?>` islands inside surrounding markup and preserves original line numbers. This was verified with a two-echo sample parsing at `has_error: False`.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/models.py` (modify) | Add `TaintKind` and `ALL_KINDS`. Nothing else changes. |
| `src/laravel/vocabulary.py` (modify) | Sinks gain a required kind. New sanitizer table. |
| `src/taint.py` (modify) | `expr_kinds` evaluator; taint state becomes a kind mapping; walking into templates. |
| `src/laravel/blade.py` (create) | Blade to PHP rewriting. Line-preserving. Pure text in, text out. No tree-sitter, no filesystem. |
| `src/laravel/views.py` (create) | `view()` call binding: template name plus which controller expression feeds which template variable. |
| `src/parser.py` (modify) | Split `parse_php` so derived text can be parsed under an original path. Stays Laravel-unaware. |
| `src/graph.py` (modify) | Collect `.blade.php` separately from `.php`, store rewritten trees and original lines. |
| `src/rules.py` (modify) | The `php.xss` rule and its finding assembly. |

`blade.py` and `views.py` are separate because they have genuinely different jobs and different inputs: one transforms text with no knowledge of the project, the other reads an AST and needs project context. Merging them would produce one module with two unrelated reasons to change.

---

### Task 1: Taint kinds and the vocabulary tables

Introduces the kind vocabulary and reshapes the sink table, without touching the taint engine yet. After this task the engine is temporarily broken against the new table, which the next task repairs. Keeping them separate means the table and the engine each get their own review.

**Files:**
- Modify: `src/models.py`
- Modify: `src/laravel/vocabulary.py`
- Modify: `tests/test_vocabulary.py`

**Interfaces:**
- Produces: `TaintKind` (StrEnum with `SQL` and `HTML`), `ALL_KINDS: frozenset[TaintKind]` in `vigilloo.models`; `sink(method: str) -> tuple[int, TaintKind] | None`, `sanitizer_clears(name: str) -> frozenset[TaintKind]`, and the unchanged `is_source(method: str) -> bool` in `vigilloo.laravel.vocabulary`.
- Note: `sink_arg_index` is **removed**, replaced by `sink`. It has no callers outside `taint.py` and `tests/test_vocabulary.py`.

- [ ] **Step 1: Write the failing test**

Replace the whole of `tests/test_vocabulary.py`:

```python
from vigilloo.laravel.vocabulary import is_source, sanitizer_clears, sink
from vigilloo.models import ALL_KINDS, TaintKind


def test_request_input_is_a_source() -> None:
    assert is_source("input")
    assert is_source("query")
    assert is_source("all")
    assert not is_source("validated")


def test_raw_sinks_declare_the_dangerous_argument_and_its_kind() -> None:
    """whereRaw('age > ?', [$age]) is safe; only argument 0 is a sink."""
    assert sink("orderByRaw") == (0, TaintKind.SQL)
    assert sink("whereRaw") == (0, TaintKind.SQL)
    assert sink("orderBy") is None
    assert sink("where") is None


def test_escaping_helpers_clear_html_but_not_sql() -> None:
    """The distinction a boolean taint flag cannot express."""
    assert sanitizer_clears("e") == frozenset({TaintKind.HTML})
    assert TaintKind.SQL not in sanitizer_clears("htmlspecialchars")


def test_numeric_coercion_clears_both_kinds() -> None:
    assert sanitizer_clears("intval") == frozenset({TaintKind.SQL, TaintKind.HTML})


def test_anti_sanitizers_clear_nothing() -> None:
    """strip_tags and addslashes are findings in themselves, never sanitizers.

    Treating either as clearing a kind converts a vulnerability into a clean
    result, which is the worst failure mode this tool has.
    """
    assert sanitizer_clears("strip_tags") == frozenset()
    assert sanitizer_clears("addslashes") == frozenset()
    assert sanitizer_clears("nonexistent_function") == frozenset()


def test_all_kinds_is_what_the_engine_can_reason_about() -> None:
    """Only kinds with both sinks and sanitizers wired are declared.

    Declaring `code` or `shell` with nothing able to consume or clear them
    would mark sources with coverage the engine does not have.
    """
    assert ALL_KINDS == frozenset({TaintKind.SQL, TaintKind.HTML})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_vocabulary.py -v`
Expected: FAIL, `ImportError: cannot import name 'sink' from 'vigilloo.laravel.vocabulary'`

- [ ] **Step 3: Add the kind vocabulary to models**

In `src/models.py`, add `from enum import StrEnum` to the imports, and add after the imports and before `class Span`:

```python
class TaintKind(StrEnum):
    """A category of danger a tainted value carries.

    docs/06-taint-analysis tables eleven kinds. Only those with both sinks and
    sanitizers wired are declared here: marking a source `code`-tainted when no
    sink can consume it and no sanitizer can clear it would claim reasoning the
    engine cannot do. Each remaining kind arrives with its sinks.

    ponytail: two kinds. js, shell, path, url, code, ldap, xpath, header and log
    land with their own sink tables - see docs/06-taint-analysis.
    """

    SQL = "sql"
    HTML = "html"


ALL_KINDS: frozenset[TaintKind] = frozenset(TaintKind)
```

- [ ] **Step 4: Reshape the vocabulary tables**

In `src/laravel/vocabulary.py`, add the import `from ..models import TaintKind` below the module docstring. Replace the `SQL_SINKS` table and the `sink_arg_index` function with:

```python
# Sink method name -> (index of the argument that reaches the parser, kind required).
# The *Raw builders accept bindings in argument 1, which are safe, so only
# argument 0 is dangerous.
#
# ponytail: DB::raw/statement/unprepared/select are the genuinely dangerous
# static-facade forms, but they are scoped_call_expression nodes and the
# taint walk only iterates member_call_expression, so they are unreachable
# today. Listing them here would advertise coverage the engine doesn't have
# (and "select" also collides with the safe builder ->select(['col'])), so
# they are left out rather than left as false advertising. They come back
# together with scoped_call_expression / static-call handling.
SINKS: dict[str, tuple[int, TaintKind]] = {
    "orderByRaw": (0, TaintKind.SQL),
    "whereRaw": (0, TaintKind.SQL),
    "orWhereRaw": (0, TaintKind.SQL),
    "havingRaw": (0, TaintKind.SQL),
    "groupByRaw": (0, TaintKind.SQL),
    "selectRaw": (0, TaintKind.SQL),
    "fromRaw": (0, TaintKind.SQL),
}

# Function name -> the kinds calling it genuinely clears, per the sanitizer
# table in docs/06-taint-analysis.
#
# strip_tags, addslashes and mysql_real_escape_string are deliberately absent.
# The spec classes them as anti-sanitizers and findings in their own right;
# listing them here would turn a vulnerability into a clean result.
SANITIZERS: dict[str, frozenset[TaintKind]] = {
    "e": frozenset({TaintKind.HTML}),
    "htmlspecialchars": frozenset({TaintKind.HTML}),
    "htmlentities": frozenset({TaintKind.HTML}),
    "intval": frozenset({TaintKind.SQL, TaintKind.HTML}),
    "floatval": frozenset({TaintKind.SQL, TaintKind.HTML}),
}


def sink(method: str) -> tuple[int, TaintKind] | None:
    return SINKS.get(method)


def sanitizer_clears(name: str) -> frozenset[TaintKind]:
    return SANITIZERS.get(name, frozenset())
```

Also update the module docstring's last line from `This module carries the subset needed for the SQL taint kind.` to `This module carries the subset needed for the sql and html taint kinds.`

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/test_vocabulary.py -v`
Expected: PASS, 6 tests

`uv run pytest` as a whole will still fail here: `taint.py` imports `sink_arg_index`, which no longer exists. That is expected and Task 2 fixes it.

- [ ] **Step 6: Commit**

```bash
git add src/models.py src/laravel/vocabulary.py tests/test_vocabulary.py
git commit -m "feat: add taint kinds and the sanitizer table"
```

---

### Task 2: Kind-aware expression evaluation

The risky task, sequenced alone and before any Blade code exists. It rewrites the taint engine's core data structure. The existing SQL suite is the gate: slice 1's finding must come out byte-identical, including its `id` and `fingerprint`.

**Files:**
- Modify: `src/taint.py`
- Modify: `tests/test_taint.py`

**Interfaces:**
- Consumes: `TaintKind`, `ALL_KINDS` from `vigilloo.models`; `sink`, `sanitizer_clears`, `is_source` from `vigilloo.laravel.vocabulary`.
- Produces: `expr_kinds(node: Node, source: bytes, local: dict[str, frozenset[TaintKind]]) -> frozenset[TaintKind]` in `vigilloo.taint`. The walk's `tainted` parameter changes from `set[str]` to `dict[str, frozenset[TaintKind]]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_taint.py`:

```python
def test_numeric_coercion_defeats_the_sql_sink(tmp_path: Path) -> None:
    """intval() makes interpolation safe, and a boolean flag cannot see that.

    This is a false positive the slice 1 engine reports today.
    """
    project_root = _minimal_project(
        tmp_path,
        controller_body=(
            "        $sort = $request->input('sort');\n"
            "        return $this->things->search($sort);"
        ),
        sink_call='DB::table("t")->orderByRaw("age > " . intval($sort))',
    )
    assert find_taint_paths(load_project(project_root)) == []


def test_html_escaping_does_not_clear_the_sql_kind(tmp_path: Path) -> None:
    """e() is not a SQL sanitizer. Clearing sql here would be a false negative."""
    project_root = _minimal_project(
        tmp_path,
        controller_body=(
            "        $sort = $request->input('sort');\n"
            "        return $this->things->search($sort);"
        ),
        sink_call='DB::table("t")->orderByRaw("created_at " . e($sort))',
    )
    assert len(find_taint_paths(load_project(project_root))) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_taint.py -v`
Expected: FAIL. Every test in the file errors with `ImportError: cannot import name 'sink_arg_index'`, because Task 1 removed it.

- [ ] **Step 3: Rewrite the taint state and add the evaluator**

In `src/taint.py`:

Replace the import line `from .laravel.vocabulary import is_source, sink_arg_index` with:

```python
from .laravel.vocabulary import is_source, sanitizer_clears, sink
```

Replace `from .models import PathStep, WalkStats` with:

```python
from .models import ALL_KINDS, PathStep, TaintKind, WalkStats
```

Delete the `_referenced_vars` function entirely and add in its place:

```python
def _union_of_children(
    node: Node, source: bytes, local: dict[str, frozenset[TaintKind]]
) -> frozenset[TaintKind]:
    kinds: frozenset[TaintKind] = frozenset()
    for child in node.children:
        kinds |= expr_kinds(child, source, local)
    return kinds


def expr_kinds(
    node: Node, source: bytes, local: dict[str, frozenset[TaintKind]]
) -> frozenset[TaintKind]:
    """Which taint kinds are still live in the value this expression produces.

    Replaces slice 1's "does this expression mention a tainted variable", which
    could not express sanitizing: e($x) mentions $x, so a flat membership test
    sees taint no matter what wraps it.

    The default case is a union over children, so an unrecognised construct
    preserves taint rather than dropping it. Silently losing taint is a false
    negative, and a security tool that under-reports without saying so is worse
    than one that over-reports.
    """
    if node.type == "variable_name":
        return local.get(_var_name(node, source), frozenset())

    if node.type == "function_call_expression":
        name = node_text(node.child_by_field_name("function"), source)
        cleared = sanitizer_clears(name)
        if cleared:
            args = node.child_by_field_name("arguments")
            inner = _union_of_children(args, source, local) if args is not None else frozenset()
            return inner - cleared

    if node.type == "cast_expression":
        # cast_type text is "int", without the parentheses.
        cast = node_text(node.child_by_field_name("type"), source).strip().lower()
        if cast in ("int", "integer", "float", "double"):
            value = node.child_by_field_name("value")
            inner = expr_kinds(value, source, local) if value is not None else frozenset()
            return inner - {TaintKind.SQL, TaintKind.HTML}

    return _union_of_children(node, source, local)
```

- [ ] **Step 4: Thread the kind mapping through the walk**

Still in `src/taint.py`, change the signature of `_walk_method` so `tainted` is a mapping:

```python
def _walk_method(
    project: Project,
    fqn: str,
    tainted: dict[str, frozenset[TaintKind]],
    prefix: list[PathStep],
    depth: int,
    max_depth: int,
    stats: WalkStats | None = None,
) -> list[list[PathStep]]:
```

Replace `local = set(tainted)` with `local = dict(tainted)`.

In the assignment block, replace the source branch's `local.add(target)` with `local[target] = ALL_KINDS`, and replace the trailing propagation branch:

```python
            if _referenced_vars(right, source) & local:
                local.add(target)
            else:
                local.discard(target)
```

with:

```python
            kinds = expr_kinds(right, source, local)
            if kinds:
                local[target] = kinds
            else:
                # Reassigned from a clean or fully sanitized value: whatever
                # taint the target carried before this statement no longer
                # applies. Without this, `$sort = $request->input('sort');
                # $sort = 'asc';` would still report $sort as tainted below.
                local.pop(target, None)
```

Replace the sink block:

```python
            index = sink_arg_index(name)
            if index is not None and index < len(args):
                if _referenced_vars(args[index], source) & local:
```

with:

```python
            found = sink(name)
            if found is not None:
                index, kind = found
                if index < len(args) and kind in expr_kinds(args[index], source, local):
```

Keep the `PathStep` construction and the `continue` that follow it exactly as they are, adjusting only their indentation to match the new nesting.

Replace the `passed` computation:

```python
            passed = {i for i, arg in enumerate(args) if _referenced_vars(arg, source) & local}
```

with:

```python
            # Which arguments carry tainted data, and which kinds. Computed
            # before the give-up checks because a give-up only counts as a lost
            # trail when there was something to lose: counting every unresolved
            # receiver fires on benign calls like $request->input() and a
            # ->get() chain terminator, and a counter that reports gaps on
            # correct code trains people to ignore it.
            passed = {
                i: kinds
                for i, arg in enumerate(args)
                if (kinds := expr_kinds(arg, source, local))
            }
```

Delete the now-duplicated older comment block above it.

Replace the callee mapping:

```python
            callee_tainted = {callee.params[i] for i in passed if i < len(callee.params)}
```

with:

```python
            callee_tainted = {
                callee.params[i]: kinds
                for i, kinds in passed.items()
                if i < len(callee.params)
            }
```

Finally, in `find_taint_paths`, change the initial call's empty set to an empty mapping:

```python
        paths.extend(_walk_method(project, route.action_fqn, {}, [entry], 0, max_depth, stats))
```

- [ ] **Step 5: Run the whole suite to verify nothing regressed**

Run: `uv run pytest -v`
Expected: PASS, 39 tests. Both new taint tests pass, and every slice 1 test still passes unchanged. If `test_finds_the_interprocedural_path_to_the_sink` fails, the refactor changed behaviour and must be fixed rather than the test adjusted.

- [ ] **Step 6: Verify lint and types**

Run: `uv run ruff format --check . && uv run ruff check && uv run mypy`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/taint.py tests/test_taint.py
git commit -m "refactor: evaluate expressions for taint kinds instead of matching variable names"
```

---

### Task 3: Blade to PHP rewriting

Pure text transformation. No tree-sitter, no filesystem, no project context, which is what makes it testable in isolation.

**Files:**
- Create: `src/laravel/blade.py`
- Create: `tests/test_blade.py`

**Interfaces:**
- Produces: `to_php(text: str) -> str` in `vigilloo.laravel.blade`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_blade.py`:

```python
from vigilloo.laravel.blade import to_php


def test_escaped_echo_becomes_an_e_call() -> None:
    """{{ }} compiles to e() in Laravel, so auto-escaping needs no special case."""
    assert to_php("{{ $x }}") == "<?php e( $x ); ?>"


def test_raw_echo_becomes_a_bare_echo() -> None:
    assert to_php("{!! $x !!}") == "<?php echo  $x ; ?>"


def test_comments_are_stripped() -> None:
    assert to_php("{{-- $secret --}}").strip() == ""


def test_literal_braces_are_left_alone() -> None:
    """@{{ x }} is for JS frameworks and must not become PHP."""
    assert "e(" not in to_php("@{{ x }}")


def test_php_blocks_are_inlined() -> None:
    assert to_php("@php $a = 1; @endphp") == "<?php  $a = 1; ?>"


def test_line_numbers_are_preserved() -> None:
    """The whole design rests on this: no span mapping table to drift."""
    template = "\n".join(
        [
            "<div>",
            "  {{-- a comment --}}",
            "  {!! $raw !!}",
            "  <p>text</p>",
            "  {{ $safe }}",
            "</div>",
        ]
    )
    out = to_php(template).splitlines()

    assert len(out) == 6
    assert "echo" in out[2]
    assert "e(" in out[4]


def test_multiline_construct_preserves_the_line_count() -> None:
    template = "a\n{{--\nlong\ncomment\n--}}\nb"
    assert len(to_php(template).splitlines()) == 6


def test_surrounding_markup_is_left_as_inert_text() -> None:
    """The text-mode grammar treats non-PHP as inert, so blanking it is wasted work."""
    assert "<div>" in to_php("<div>{{ $x }}</div>")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_blade.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'vigilloo.laravel.blade'`

- [ ] **Step 3: Write the implementation**

Create `src/laravel/blade.py`:

```python
"""Blade template rewriting.

Blade is not PHP. Laravel compiles it; Vigilloo rewrites it into a normalised
form the PHP grammar can read, preserving the escaping mode of every echo,
because that distinction is the XSS rule - see docs/03-parser.

The transformation is line-preserving: output line N came from input line N.
That is what lets evidence paths cite real .blade.php line numbers with no
mapping table to drift out of sync. Columns are not preserved, which is
accepted: reports render a line number and a snippet, and the snippet is taken
from the original Blade text.

Surrounding markup is left alone rather than blanked. The text-mode PHP grammar
treats anything outside <?php ... ?> as inert, so each rewritten echo is an
island in text the parser already ignores.

ponytail: regex-level rewriting, not a Blade parser. Handles the echo forms,
comments and @php blocks, which is what this slice's rules reach. If this hits
@verbatim or deeply nested directives, vendoring EmranMR/tree-sitter-blade is
the escape hatch - see the slice 2 design.
"""

import re

# Order matters. Comments are stripped before echoes so a commented-out echo
# does not become a sink. The literal @{{ form is protected before {{ is
# rewritten, or a JS template would be analysed as PHP.
_COMMENT = re.compile(r"\{\{--.*?--\}\}", re.S)
_LITERAL = re.compile(r"@\{\{.*?\}\}", re.S)
_RAW_ECHO = re.compile(r"\{!!(.*?)!!\}", re.S)
_ESCAPED_ECHO = re.compile(r"\{\{(.*?)\}\}", re.S)
_PHP_BLOCK = re.compile(r"@php(.*?)@endphp", re.S)

_LITERAL_PLACEHOLDER = "\x00vigilloo-blade-literal\x00"


def _keep_lines(replacement: str, matched: str) -> str:
    """Pad a replacement so it spans as many lines as the text it replaced."""
    return replacement + "\n" * matched.count("\n")


def to_php(text: str) -> str:
    """Rewrite Blade into PHP the tree-sitter php grammar can read."""
    literals: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        literals.append(match.group(0))
        return _keep_lines(_LITERAL_PLACEHOLDER, match.group(0))

    text = _LITERAL.sub(_stash, text)
    text = _COMMENT.sub(lambda m: _keep_lines("", m.group(0)), text)
    text = _PHP_BLOCK.sub(lambda m: _keep_lines(f"<?php {m.group(1)} ?>", m.group(0)), text)
    text = _RAW_ECHO.sub(lambda m: _keep_lines(f"<?php echo {m.group(1)}; ?>", m.group(0)), text)
    text = _ESCAPED_ECHO.sub(lambda m: _keep_lines(f"<?php e({m.group(1)}); ?>", m.group(0)), text)

    for literal in literals:
        text = text.replace(_LITERAL_PLACEHOLDER, literal.replace("\n", ""), 1)
    return text
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_blade.py -v`
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
git add src/laravel/blade.py tests/test_blade.py
git commit -m "feat: rewrite Blade templates into line-preserving PHP"
```

---

### Task 4: Load Blade templates into the project graph

**Files:**
- Modify: `src/parser.py`
- Modify: `src/graph.py`
- Modify: `tests/test_graph.py`

**Interfaces:**
- Consumes: `to_php` from `vigilloo.laravel.blade`.
- Produces: `parse_source(path: Path, source: bytes) -> ParsedFile` in `vigilloo.parser`; `Project.blade: dict[Path, ParsedFile]`, `Project.blade_lines: dict[Path, list[str]]`, and `Project.blade_line(path: Path, line: int) -> str` in `vigilloo.graph`.

Note: `.blade.php` files match `rglob("*.php")`, so they are currently parsed as if they were PHP. This task stops that and routes them through the rewriter instead.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_graph.py`:

```python
def test_blade_templates_are_rewritten_not_parsed_as_php(tmp_path: Path) -> None:
    views = tmp_path / "resources" / "views" / "orders"
    views.mkdir(parents=True)
    (views / "show.blade.php").write_text("<div>\n{!! $sort !!}\n</div>\n")

    project = load_project(tmp_path)
    rel = Path("resources/views/orders/show.blade.php")

    assert rel in project.blade
    assert rel not in project.files
    assert not project.blade[rel].has_errors


def test_blade_originals_back_the_snippets(tmp_path: Path) -> None:
    """Snippets must show Blade, not the PHP it was rewritten into."""
    views = tmp_path / "resources" / "views"
    views.mkdir(parents=True)
    (views / "show.blade.php").write_text("<div>\n  {!! $sort !!}\n</div>\n")

    project = load_project(tmp_path)
    rel = Path("resources/views/show.blade.php")

    assert project.blade_line(rel, 2) == "{!! $sort !!}"
    assert project.blade_line(rel, 999) == ""
```

Add `from pathlib import Path` to the imports of `tests/test_graph.py` if it is not already present.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_graph.py -v`
Expected: FAIL, `AttributeError: 'Project' object has no attribute 'blade'`

- [ ] **Step 3: Split the parser so derived text can be parsed**

In `src/parser.py`, replace `parse_php` with:

```python
def parse_source(path: Path, source: bytes) -> ParsedFile:
    """Parse text that is already in hand, attributed to `path`.

    Separate from parse_php so a caller holding derived text - Blade rewritten
    into PHP - can have it parsed while spans still point at the original file.
    The parser stays unaware of what produced the text.
    """
    tree = _parser().parse(source)
    return ParsedFile(
        path=path,
        source=source,
        tree=tree,
        has_errors=tree.root_node.has_error,
    )


def parse_php(path: Path) -> ParsedFile:
    """Parse one PHP file. Never raises for malformed input."""
    return parse_source(path, path.read_bytes())
```

- [ ] **Step 4: Collect Blade files in the graph**

In `src/graph.py`:

Add to the imports:

```python
from .laravel.blade import to_php
from .parser import ParsedFile, parse_php, parse_source
```

replacing the existing `from .parser import ParsedFile, parse_php`.

Add two fields to `Project`, after `routes`:

```python
    blade: dict[Path, ParsedFile] = field(default_factory=dict)
    blade_lines: dict[Path, list[str]] = field(default_factory=dict)
```

Add a method to `Project`, after `resolve_property_type`:

```python
    def blade_line(self, path: Path, line: int) -> str:
        """The original Blade text of a 1-indexed line, for evidence snippets.

        Findings must quote what the developer wrote, not the PHP it was
        rewritten into. Out-of-range lines return empty rather than raising:
        a snippet is presentation, and it must never be able to abort a scan.
        """
        lines = self.blade_lines.get(path, [])
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""
```

Change `_php_files` to exclude Blade, and add its counterpart:

```python
def _php_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
        and not p.name.endswith(".blade.php")
    ]
    return sorted(found)  # sorted for determinism


def _blade_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.blade.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
    ]
    return sorted(found)  # sorted for determinism
```

At the end of `load_project`, immediately before `project.routes.sort(...)`, add:

```python
    for path in _blade_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            project.failed.append(path)
            continue

        rel_path = path.relative_to(root)
        parsed = parse_source(rel_path, to_php(text).encode("utf-8"))

        # A template that will not parse degrades this file, never the scan.
        if parsed.has_errors:
            project.unparsed.append(rel_path)

        project.blade[rel_path] = parsed
        project.blade_lines[rel_path] = text.splitlines()
```

- [ ] **Step 5: Run the whole suite to verify it passes**

Run: `uv run pytest -v`
Expected: PASS, 41 tests.

- [ ] **Step 6: Verify lint and types**

Run: `uv run ruff format --check . && uv run ruff check && uv run mypy`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/parser.py src/graph.py tests/test_graph.py
git commit -m "feat: load Blade templates into the project graph"
```

---

### Task 5: Bind controller variables to template variables

**Files:**
- Create: `src/laravel/views.py`
- Create: `tests/test_views.py`

**Interfaces:**
- Produces: `ViewBinding` (frozen dataclass with `template: str`, `variables: dict[str, Node]`, `compacted: tuple[str, ...]`), `template_path(name: str) -> Path`, and `extract_view_binding(stmt: Node, source: bytes) -> ViewBinding | None`, all in `vigilloo.laravel.views`.

`variables` maps a template variable name to the controller **expression node** bound to it. `compacted` lists names passed through `compact()`, where the template variable and the controller variable share a name and there is no separate expression to evaluate.

- [ ] **Step 1: Write the failing test**

Create `tests/test_views.py`:

```python
from pathlib import Path

from vigilloo.laravel.views import extract_view_binding, template_path
from vigilloo.parser import find_all, parse_source


def _first_statement(php: str):
    parsed = parse_source(Path("t.php"), php.encode())
    stmt = find_all(parsed.tree.root_node, "return_statement")[0]
    return stmt, parsed.source


def test_dotted_names_become_template_paths() -> None:
    assert template_path("orders.show") == Path("resources/views/orders/show.blade.php")
    assert template_path("welcome") == Path("resources/views/welcome.blade.php")


def test_array_literal_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show', ['sort' => $sort]);")
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.template == "orders.show"
    assert set(binding.variables) == {"sort"}
    assert binding.compacted == ()


def test_compact_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show', compact('sort'));")
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.compacted == ("sort",)
    assert binding.variables == {}


def test_fluent_with_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show')->with('sort', $sort);")
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.template == "orders.show"
    assert set(binding.variables) == {"sort"}


def test_double_quoted_names_resolve_too() -> None:
    """Single and double quoted literals are different node types in the grammar."""
    stmt, source = _first_statement('<?php return view("orders.show", ["sort" => $sort]);')
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.template == "orders.show"


def test_computed_template_name_is_unresolvable() -> None:
    """view($name) cannot be resolved without guessing, so it is not resolved."""
    stmt, source = _first_statement("<?php return view($name, ['sort' => $sort]);")
    assert extract_view_binding(stmt, source) is None


def test_statement_without_a_view_call_binds_nothing() -> None:
    stmt, source = _first_statement("<?php return $this->orders->search($sort);")
    assert extract_view_binding(stmt, source) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_views.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'vigilloo.laravel.views'`

- [ ] **Step 3: Write the implementation**

Create `src/laravel/views.py`:

```python
"""Which controller data reaches which template.

Taint has to cross the view() call or an XSS finding cannot have a complete
evidence path, and a finding without a path is not a finding - see
docs/08-framework-adapters.

ponytail: the three common call forms only. @include, @extends and components
do not carry taint across template files in this slice, so taint stops at the
template it was handed to.
"""

from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from ..parser import find_all, node_text

_VIEW_ROOT = Path("resources/views")


@dataclass(frozen=True)
class ViewBinding:
    """A resolved view() call: the template, and what was handed to it."""

    template: str
    variables: dict[str, Node] = field(default_factory=dict)
    compacted: tuple[str, ...] = ()


def template_path(name: str) -> Path:
    """'orders.show' -> resources/views/orders/show.blade.php."""
    return _VIEW_ROOT / (name.replace(".", "/") + ".blade.php")


def _literal(node: Node, source: bytes) -> str | None:
    """The value of a string literal, or None if this is not one.

    Single quoted literals parse as `string` and double quoted ones as
    `encapsed_string`, so the value is read from the shared string_content
    child rather than by matching either node type.
    """
    if node.type not in ("string", "encapsed_string"):
        return None
    content = find_all(node, "string_content")
    return node_text(content[0], source) if content else ""


def _arguments(call: Node) -> list[Node]:
    args_node = call.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [a for a in args_node.children if a.is_named]


def _unwrap(argument: Node) -> Node:
    """An `argument` node wraps the expression it carries."""
    named = [c for c in argument.children if c.is_named]
    return named[0] if named else argument


def extract_view_binding(stmt: Node, source: bytes) -> ViewBinding | None:
    """Resolve the view() call in this statement, if there is a resolvable one.

    Returns None when the statement has no view() call, or when the template
    name is computed rather than literal. The caller records the second case as
    a coverage gap; guessing at it would be worse than reporting it.
    """
    view_call = next(
        (
            c
            for c in find_all(stmt, "function_call_expression")
            if node_text(c.child_by_field_name("function"), source) == "view"
        ),
        None,
    )
    if view_call is None:
        return None

    args = _arguments(view_call)
    if not args:
        return None
    name = _literal(_unwrap(args[0]), source)
    if name is None:
        return None

    variables: dict[str, Node] = {}
    compacted: list[str] = []

    if len(args) > 1:
        data = _unwrap(args[1])
        if data.type == "array_creation_expression":
            for element in find_all(data, "array_element_initializer"):
                parts = [c for c in element.children if c.is_named]
                if len(parts) == 2:
                    key = _literal(parts[0], source)
                    if key is not None:
                        variables[key] = parts[1]
        elif (
            data.type == "function_call_expression"
            and node_text(data.child_by_field_name("function"), source) == "compact"
        ):
            for argument in _arguments(data):
                key = _literal(_unwrap(argument), source)
                if key:
                    compacted.append(key)

    # ->with('key', $value) chained onto the same statement.
    for call in find_all(stmt, "member_call_expression"):
        if node_text(call.child_by_field_name("name"), source) != "with":
            continue
        with_args = _arguments(call)
        if len(with_args) == 2:
            key = _literal(_unwrap(with_args[0]), source)
            if key:
                variables[key] = _unwrap(with_args[1])

    return ViewBinding(template=name, variables=variables, compacted=tuple(compacted))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_views.py -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Verify lint and types**

Run: `uv run ruff format --check . && uv run ruff check && uv run mypy`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/laravel/views.py tests/test_views.py
git commit -m "feat: resolve view() calls to templates and their bound variables"
```

---

### Task 6: Walk into templates, add the XSS rule, prove it end to end

**Files:**
- Modify: `src/taint.py`
- Modify: `src/rules.py`
- Create: `tests/fixtures/laravel-minimal/resources/views/orders/show.blade.php`
- Modify: `tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php`
- Modify: `tests/fixtures/laravel-minimal/routes/api.php`
- Modify: `tests/test_taint.py`
- Modify: `tests/test_scan.py`

**Interfaces:**
- Consumes: `ViewBinding`, `template_path`, `extract_view_binding` from `vigilloo.laravel.views`; `Project.blade`, `Project.blade_line` from `vigilloo.graph`.
- Produces: `php.xss` findings from `scan_project`.

- [ ] **Step 1: Write the fixture**

Create `tests/fixtures/laravel-minimal/resources/views/orders/show.blade.php`:

```blade
<div class="orders">
  <p>Raw: {!! $sort !!}</p>
  <p>Escaped: {{ $sort }}</p>
  <p>Manual: {!! e($sort) !!}</p>
</div>
```

Add the action to `tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php`, immediately before the closing brace of the class:

```php
    public function display(Request $request)
    {
        $sort = $request->input('sort');

        return view('orders.show', compact('sort'));
    }
```

Add the route to `tests/fixtures/laravel-minimal/routes/api.php`:

```php
Route::get('/orders/display', [OrderController::class, 'display']);
```

- [ ] **Step 2: Write the failing test**

Append to `tests/test_taint.py`:

```python
def test_raw_blade_echo_is_reached_from_the_route() -> None:
    """The full slice 2 path: route, controller, view() call, template sink."""
    paths = find_taint_paths(load_project(FIXTURE))
    blade = [p for p in paths if p[-1].span.file.name == "show.blade.php"]

    assert len(blade) == 1
    roles = [step.role for step in blade[0]]
    assert roles == ["entry", "source", "propagator", "sink"]

    sink = blade[0][-1]
    assert sink.span.start_line == 2
    assert sink.snippet == "<p>Raw: {!! $sort !!}</p>"


def test_escaped_and_manually_escaped_echoes_are_silent() -> None:
    """The test that distinguishes a kind set from a boolean flag.

    Lines 3 and 4 of the fixture template render the same tainted value through
    {{ }} and through {!! e() !!}. Both are safe, and a boolean taint flag
    would report both.
    """
    paths = find_taint_paths(load_project(FIXTURE))
    lines = {p[-1].span.start_line for p in paths if p[-1].span.file.name == "show.blade.php"}
    assert lines == {2}
```

Append to `tests/test_scan.py`:

```python
def test_scan_reports_the_xss_finding() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    out = result.stdout

    assert "Cross-Site Scripting" in out
    assert "CWE-79" in out
    assert "show.blade.php" in out
    assert "2 findings" in out
```

Update `test_scan_reports_the_finding_with_its_full_path` in the same file: change its final assertion from `assert "1 finding" in out` to `assert "SQL Injection" in out`, since the run now reports two findings and the count is asserted by the new test.

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_taint.py::test_raw_blade_echo_is_reached_from_the_route -v`
Expected: FAIL, `assert 0 == 1` because no path reaches a Blade file.

- [ ] **Step 4: Walk into templates**

In `src/taint.py`, add to the imports:

```python
from .laravel.views import extract_view_binding, template_path
```

Add a template walker, placed immediately before `_walk_method`:

```python
def _walk_template(
    project: Project,
    template: Path,
    bound: dict[str, frozenset[TaintKind]],
    prefix: list[PathStep],
) -> list[list[PathStep]]:
    """Every raw echo in this template that still carries html taint.

    The html sink is scoped to Blade-derived files on purpose. `echo` in a
    plain PHP script is not usefully a finding, and flagging every one is how a
    tool teaches people to ignore it.

    ponytail: Response bodies and non-Blade templates when a fixture needs them.
    """
    parsed = project.blade.get(template)
    if parsed is None:
        return []

    paths: list[list[PathStep]] = []
    for stmt in find_all(parsed.tree.root_node, "echo_statement"):
        if TaintKind.HTML not in expr_kinds(stmt, parsed.source, bound):
            continue
        line = stmt.start_point[0] + 1
        paths.append(
            prefix
            + [
                PathStep(
                    role="sink",
                    span=node_span(stmt, parsed.path),
                    snippet=project.blade_line(parsed.path, line),
                    note="raw echo, no HTML escaping",
                )
            ]
        )
    return paths
```

Add `Path` to the imports of `src/taint.py` (`from pathlib import Path`).

Inside `_walk_method`, at the end of the per-statement loop body and after the existing `for call in find_all(stmt, "member_call_expression"):` block, add the view handling:

```python
        # 3. view() hands data to a template, where html taint can reach a
        #    raw echo.
        binding = extract_view_binding(stmt, source)
        if binding is None:
            continue

        bound: dict[str, frozenset[TaintKind]] = {}
        for name, expression in binding.variables.items():
            kinds = expr_kinds(expression, source, local)
            if kinds:
                bound[name] = kinds
        for name in binding.compacted:
            kinds = local.get(name, frozenset())
            if kinds:
                bound[name] = kinds

        if not bound:
            continue

        template = template_path(binding.template)
        if template not in project.blade:
            # An unresolvable template that was handed tainted data is a real
            # gap in coverage, and invariant 4 says gaps are reported.
            _giveup(stats)
            continue

        step = PathStep(
            role="propagator",
            span=node_span(stmt, parsed.path),
            snippet=node_text(stmt, source).strip(),
            note=f"view data into {template}",
        )
        paths.extend(_walk_template(project, template, bound, prefix + [step]))
```

- [ ] **Step 5: Add the rule**

In `src/rules.py`, add the rule definition after `SQL_INJECTION`:

```python
XSS = Rule(
    id="php.xss",
    title="Cross-Site Scripting",
    severity="high",
    cwe=("CWE-79",),
    remediation=(
        "Render the value with {{ }} instead of {!! !!}. Blade escapes {{ }} "
        "automatically. Reach for {!! !!} only for markup you generated "
        "yourself, never for anything derived from a request."
    ),
)
```

The remediation points at `{{ }}` rather than at `e()` on purpose: telling a Laravel developer to wrap a raw echo in `e()` when the fix is to stop using `{!! !!}` is correct and useless.

Replace the body of `scan_project` with:

```python
def scan_project(project: Project, stats: WalkStats | None = None) -> list[Finding]:
    """Run every rule over the project graph."""
    findings = []
    for path in find_taint_paths(project, stats=stats):
        rule = XSS if path[-1].span.file.name.endswith(".blade.php") else SQL_INJECTION
        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                cwe=rule.cwe,
                span=path[-1].span,
                evidence_path=tuple(path),
                remediation=rule.remediation,
            )
        )
    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
```

`Span` holds a `file: Path`, so the test is `span.file.name`, not `span.name`.

Routing on the file extension rather than on a kind carried in the path is deliberate for this
slice: there is exactly one sink per rule and they live in different file types. When a third
rule arrives, `PathStep` gains the rule identity and this branch goes away.

- [ ] **Step 6: Run the whole suite to verify it passes**

Run: `uv run pytest -v`
Expected: PASS, 45 tests.

- [ ] **Step 7: Verify the coverage counter did not regress**

Run: `uv run pytest tests/test_taint.py::test_clean_project_reports_no_lost_trails -v`
Expected: PASS. The fixture resolves its template, so nothing was lost and the counter stays at zero. If this fails, a benign statement is being counted as a give-up.

- [ ] **Step 8: Verify lint and types**

Run: `uv run ruff format --check . && uv run ruff check && uv run mypy`
Expected: all pass.

- [ ] **Step 9: See it work**

Run: `uv run vigilloo scan tests/fixtures/laravel-minimal`
Expected: two findings, one CRITICAL SQL Injection at `OrderRepository.php:12` and one HIGH Cross-Site Scripting at `resources/views/orders/show.blade.php:2`, the second with an evidence path of route, source, view data, raw echo. Exit code 1.

- [ ] **Step 10: Commit**

```bash
git add src/taint.py src/rules.py tests/ 
git commit -m "feat: detect XSS through Blade raw echoes"
```

---

### Task 7: Update the specification

`docs/` is normative, and this slice changed detection behaviour. CLAUDE.md requires the spec to move in the same change, so this is a task rather than an afterthought.

**Files:**
- Modify: `docs/plans/2026-07-26-slice-2-design.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Mark the design as implemented**

In `docs/plans/2026-07-26-slice-2-design.md`, change the `**Status:**` line to `**Status:** implemented.`

- [ ] **Step 2: Record the new deferrals in CLAUDE.md**

In the `## Where the Laravel value concentrates` section of `CLAUDE.md`, the line about kind-based taint already describes the target design. Change its tense so it documents current behaviour rather than an aspiration, replacing:

```
- **Taint is kind-based, not boolean.** `e()` clears `html`, not `sql`. A boolean flag produces
  both false positives and false negatives.
```

with:

```
- **Taint is kind-based, not boolean.** `e()` clears `html`, not `sql`. A boolean flag produces
  both false positives and false negatives. Implemented for `sql` and `html`; the other nine
  kinds in [06-taint-analysis](docs/06-taint-analysis/README.md) arrive with their own sinks.
```

- [ ] **Step 3: Commit**

```bash
git add docs/plans/2026-07-26-slice-2-design.md CLAUDE.md
git commit -m "docs: record slice 2 as implemented"
```

---

## Self-review notes

Checked against the design document:

- Design section 1 (kind vocabulary) is Task 1. Section 2 (taint state) and section 3 (expression evaluation, sanitizer table) are Tasks 1 and 2. Section 4 (sinks carry a kind) is Task 1 for the table and Task 2 for the check. Section 5 (Blade preprocessing) is Task 3, with loading in Task 4. Section 6 (view binding) is Task 5. Section 7 (walking into the template) and section 8 (the rule) are Task 6. Section 9 (error handling and coverage) is spread across Tasks 4 and 6, with the unresolved-template counter in Task 6 step 4 and the never-fatal parse in Task 4 step 4. Section 10 (tests) is distributed, with the four decisive assertions in Task 6. Section 11 (order of work) is the task order.
- One design detail was refined during planning: the design table said surrounding HTML is blanked, and the implementation leaves it as inert text instead. The effect is identical because the text-mode grammar ignores anything outside `<?php ... ?>`, and leaving it alone is less code. `blade.py`'s docstring records this.
- Test counts assume the suite starts at 37 and ends at 45. If the actual counts differ, the assertions in each task's expected output are what matter, not the totals.
