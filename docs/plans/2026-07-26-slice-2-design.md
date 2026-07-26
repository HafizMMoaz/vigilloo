# Slice 2 Design: Kind-Based Taint and XSS Through Blade

**Status:** implemented.
**Supersedes nothing.** Builds directly on the first vertical slice.
**Normative references:** [06-taint-analysis](../06-taint-analysis/README.md),
[03-parser](../03-parser/README.md), [08-framework-adapters](../08-framework-adapters/README.md).
Where this document and those disagree, those win and this is the bug.

## Goal

`vigilloo scan` reports a reflected XSS finding whose evidence path runs from an HTTP route,
through a controller, across a `view()` call, into a `.blade.php` template, and stops at a raw
echo. In the same run, the identical value rendered through `{{ }}` produces no finding.

The second half is the point. A taint system that can only fire has not been shown to be
kind-based. The escaped case is the test that distinguishes this design from a boolean flag.

## Why this slice

Slice 1 tracks taint as a boolean, which
[06-taint-analysis](../06-taint-analysis/README.md) explicitly rejects: `e()` makes a value safe
to print and does nothing for SQL. The deferral table in the slice 1 plan names the trigger for
fixing it as "when the second sink class (html) lands". This slice lands it. Every rule written
before the kind set exists is a rule that has to be revisited afterwards, so the cost of
deferring further grows with each one.

## Non-goals

Recorded so they read as decisions rather than oversights. Each gets a `ponytail:` comment at
the relevant place in code.

| Deferred | Why it is safe to defer |
| --- | --- |
| `@include`, `@extends`, `<x-component>` cross-template flow | Needs a template graph and section resolution. Taint stops at the template it was handed to, which covers the direct controller-to-view case. |
| The nine other taint kinds (`js`, `shell`, `path`, `url`, `code`, …) | Each arrives with its sinks. See "Kind vocabulary" below. |
| `Blade::render()`, `@json`, `@each` | No fixture needs them. |
| SQLite persistence, CFG, facade and container resolution | Unchanged from the slice 1 deferral table. |

## 1. Kind vocabulary

`TaintKind` is a `StrEnum` in `models.py` with exactly two members for now:

```python
class TaintKind(StrEnum):
    SQL = "sql"
    HTML = "html"
```

[06-taint-analysis](../06-taint-analysis/README.md) tables eleven kinds. Declaring the other
nine now would make `ALL_KINDS` claim reasoning the engine cannot do: a source would be marked
`code`-tainted with no `code` sink able to consume it, and no sanitizer able to clear it. That
is the same false-advertising argument `laravel/vocabulary.py` already makes for leaving
`DB::raw` out of the sink table, and it is applied consistently here. Each kind arrives with
its sinks and its sanitizers, together.

`ALL_KINDS` therefore means "every kind this engine can reason about", and a source is marked
with all of it.

## 2. Taint state

The walk's local state changes shape:

```python
local: set[str]                          # slice 1: names of tainted variables
local: dict[str, frozenset[TaintKind]]   # slice 2: name -> kinds still live
```

A variable absent from the mapping is clean. A variable present with an empty set is also
clean, and the two are treated identically so callers never have to distinguish them.

## 3. Expression evaluation

This is the core change and the reason the rest is small.

Slice 1 asks "does this expression mention a tainted variable", via `_referenced_vars(node) &
local`. That question cannot express sanitizing: `e($x)` mentions `$x`, so a flat membership
test sees taint no matter what wraps it. It is replaced by a recursive evaluator:

```python
def expr_kinds(node, local) -> frozenset[TaintKind]:
    """Kinds still live in the value this expression produces."""
```

| Node | Result |
| --- | --- |
| `variable_name` | `local.get(name, frozenset())` |
| call to a name in `SANITIZERS` | `expr_kinds(args) - SANITIZERS[name]` |
| `(int)` / `(float)` cast, `intval()` | `expr_kinds(operand) - {SQL, HTML}` |
| anything else | union of `expr_kinds` over children |

The default case is a union, so an unrecognised construct preserves taint rather than dropping
it. Losing taint silently is a false negative, and a security tool that under-reports without
saying so is worse than one that over-reports.

This also fixes a live false positive on the SQL side that has nothing to do with XSS:
`whereRaw("age > " . intval($v))` is currently reported and should not be.

### Sanitizer table

Added to `laravel/vocabulary.py`, sourced from the sanitizer table in
[06-taint-analysis](../06-taint-analysis/README.md):

```python
SANITIZERS: dict[str, frozenset[TaintKind]] = {
    "e":                frozenset({HTML}),
    "htmlspecialchars": frozenset({HTML}),
    "htmlentities":     frozenset({HTML}),
    "intval":           frozenset({SQL, HTML}),
    "floatval":         frozenset({SQL, HTML}),
}
```

`strip_tags` and `addslashes` are deliberately absent. The spec classes them as anti-sanitizers
and findings in their own right; treating them as clearing anything would convert a
vulnerability into a clean result.

## 4. Sinks carry a required kind

```python
SQL_SINKS: dict[str, int]                        # slice 1
SINKS: dict[str, tuple[int, TaintKind]]          # slice 2: method -> (arg index, kind)
```

A sink fires only when its kind is still present in the argument's kind set. The existing seven
`*Raw` builders keep argument 0 and gain `TaintKind.SQL`.

The `html` sink is not a method call. It is an `echo_statement` in a Blade-derived file whose
expression still carries `HTML`.

**The html sink is scoped to Blade-derived files on purpose.** `echo` in a plain PHP script is
not usefully a finding, and flagging every one is how a tool teaches people to ignore it. This
gets a `ponytail:` comment naming the upgrade path: `Response` bodies and non-Blade templates
when a fixture needs them.

## 5. Blade preprocessing

New module `src/laravel/blade.py`, one public function:

```python
def to_php(text: str) -> str:
    """Rewrite Blade into PHP the tree-sitter php grammar can read.

    Line-preserving: output line N corresponds to input line N.
    """
```

| Blade | Becomes | Rationale |
| --- | --- | --- |
| `{{ expr }}` | `<?php e(expr); ?>` | Compiles to `e()` in Laravel. Auto-escaping then needs no special case, it is just the sanitizer from section 3. |
| `{!! expr !!}` | `<?php echo expr; ?>` | The raw echo. `echo_statement` is already in the walk's statement types. |
| `@php … @endphp` | contents inlined | Real PHP already. |
| `{{-- … --}}` | blank lines | Comment. Multi-line aware. |
| `@{{ … }}` | blank | Literal for JS frameworks. Inert. |
| HTML text, other directives | blank | Not reachable by this slice's rules. |

No file-level `<?php` prologue is emitted. The parser already uses `tree_sitter_php.language_php()`,
the text-mode grammar that handles `?>` and `<?php` interleaving, so each rewritten echo is an
inline PHP island in surrounding inert text. This was verified against the real grammar before
committing to the design: a two-echo sample parses with `has_error: False`, and the `e()` call
and the `echo` land on their original lines.

Line preservation is what makes evidence paths honest. A span in the rewritten text has the
same line number as the Blade construct it came from, so no mapping table exists to drift out of
sync. Columns may shift, and that is accepted: reports render a line number and a snippet, and
the snippet is taken from the original Blade text.

### Layering

`blade.py` lives in the Laravel adapter, not the parser.
[03-parser](../03-parser/README.md) assigns directive coverage and the compiled-output mapping to
the adapter, and requires only "a faithful, span-preserving transformation" from the parser.
The parser gains one Laravel-free capability: parse this derived text, attribute spans to this
original path. It never learns what Blade is.

## 6. Controller to template binding

New module `src/laravel/views.py`. Resolves the template and the variables handed to it.

**Name resolution.** `view('orders.show')` maps to `resources/views/orders/show.blade.php`,
dots to path separators. A name that resolves to no file on disk increments the unresolved
counter, which surfaces in the coverage report. It is never silently skipped: invariant 4 says
coverage is reported, never hidden.

**Data extraction**, the three forms agreed for this slice:

```php
return view('orders.show', ['sort' => $sort]);      // array literal
return view('orders.show', compact('sort'));        // compact
return view('orders.show')->with('sort', $sort);    // fluent
```

Each yields a mapping from template variable name to the controller expression bound to it.
`compact('sort')` binds template `$sort` to controller `$sort`, which is the whole reason the
form exists.

## 7. Walking into the template

`_walk_method` currently resolves a body through `project.method(fqn)`. Templates are not
methods, so the walk gains a second entry shape rather than pretending they are.

When the walk encounters a `view()` call whose bound data carries any live kinds, it emits a
propagator `PathStep` at the `view()` call site and walks the template's top-level statements
with those variables bound to the kinds they arrived with. `Project` grows a store of parsed
Blade files, keyed by path, alongside its PHP files.

Recursion depth and the existing `max_depth` guard are unchanged. A template does not call
further templates in this slice, by the non-goal above, so the added depth is one.

## 8. The rule

`php.xss`, CWE-79, severity high, emitted from `rules.py` alongside the existing SQL rule.

Rule IDs are permanent per invariant 7: this string ships in users' baselines and
`// vigilloo-ignore` comments, so it is fixed at the moment it is written.

Remediation text points at `{{ }}` rather than at `e()`. Telling a Laravel developer to wrap a
raw echo in `e()` when the fix is to stop using `{!! !!}` is technically correct and practically
useless.

## 9. Error handling and coverage

- A Blade file that fails to parse after rewriting is recorded as partially parsed and reported,
  never fatal. One bad template does not abort a scan.
- An unresolvable view name increments the unresolved counter.
- A `view()` call with a computed name (`view($template)`) is unresolvable by construction. It
  increments the counter rather than guessing.
- Consistent with the slice 1 fix, a give-up only counts when tainted data was actually
  abandoned. Counting unresolvable views that carried nothing tainted would report gaps on
  correct code, which trains people to ignore the counter.

## 10. Tests

The fixture gains a controller action passing tainted data to templates, plus the templates.

| Case | Expected |
| --- | --- |
| `{!! $sort !!}` | XSS finding, path route to Blade line |
| `{{ $sort }}` | **no finding** |
| `{!! e($sort) !!}` | **no finding** |
| `whereRaw("age > " . intval($v))` | **no finding** |
| existing SQL path | one finding, unchanged |

Rows two, three and four are the ones that carry the slice. Row five is the regression guard:
this change rewrites the taint engine's core data structure, and slice 1's finding must come
out byte-identical, including its `id` and `fingerprint`.

Unit tests cover `blade.py` line preservation directly: for a template of N lines, the rewritten
output has N lines, and a construct on input line K produces PHP on output line K.

## 11. Order of work

1. `TaintKind`, and the kind set threaded through `models.py`.
2. `expr_kinds` replacing `_referenced_vars` at the sink and argument checks, with `SINKS`
   carrying kinds. **Slice 1 tests must still pass here**, before any Blade code exists. This is
   the checkpoint that proves the refactor is behaviour-preserving.
3. `blade.py` and its line-preservation tests, standalone.
4. `views.py` and the three binding forms.
5. Walking into templates, the `php.xss` rule, the fixture, the four assertions.

Step 2 is the risk. It is deliberately sequenced so the SQL suite is a green gate before Blade
enters the picture, rather than debugging a data structure change and a new file type together.
