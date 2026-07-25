# Data Flow Analysis

Answers: **for a given expression, where did its value come from, and where does it go?**
This doc covers the machinery. The security vocabulary layered on top - which origins are
dangerous and which destinations matter - is [06-taint-analysis](../06-taint-analysis/README.md).

## Position in the pipeline

```text
AST + symbols  →  CFG  →  SSA-ish value numbering  →  intraprocedural flow
                                                            │
                          call graph [07] ──────────────────┤
                                                            ▼
                                                  interprocedural flow  →  taint [06]
```

## Control flow graph

Per function/method/closure, over basic blocks. PHP constructs that must be modelled correctly:

- `if` / `elseif` / `else`, `switch` (fall-through!), `match` (no fall-through)
- `while`, `do-while`, `for`, `foreach` (including `as $k => $v` and `as &$v` by-reference)
- `break N` / `continue N` with levels
- `try` / `catch` / `finally` - `finally` runs on both paths, and a `return` inside `finally`
  overrides the pending one
- `throw` as an expression (PHP 8), `return`, `exit` / `die`
- short-circuit `&&`, `||`, `??`, `?:` - each creates a branch, and a sanitizer applied in only
  one arm is a real and common bug pattern
- Early-return guard clauses, the dominant Laravel controller idiom

Blocks are graph nodes; `FLOWS_TO` / `BRANCH_TRUE` / `BRANCH_FALSE` are edges.

## Intraprocedural flow

Value numbering in SSA style, adapted to PHP's dynamism. For each variable definition, record
its reaching definitions; at merge points insert φ-nodes so a value tainted on one branch stays
tainted after the join.

Tracked constructs:

| Construct | Handling |
| --- | --- |
| `$b = $a` | `$a --PROPAGATES_TO--> $b` |
| `$s = "x $a y"`, `$s = 'x' . $a` | interpolation and concatenation propagate |
| `$arr['k'] = $a` | field-sensitive to a bounded depth (default 3); deeper collapses to whole-array taint |
| `$obj->prop = $a` | property-sensitive on `$this` within a class; conservative across objects |
| `list($x, $y) = $a` / `[$x] = $a` | destructuring propagates elementwise |
| `foreach ($a as $v)` | element taint from collection taint |
| `$f = fn() => $a;` | closures capture by value; `use (&$x)` captures by reference - both modelled |
| `&$ref` params and assignments | by-reference aliasing; writes flow back to the caller |
| `global $x`, `static $x` | function-scoped persistence across calls |
| `$$name` | unresolvable → whole-scope taint, flagged low-confidence |

**Field sensitivity matters more in Laravel than in most stacks**, because `$request->all()`
produces one array carrying every parameter. Without per-key tracking, one tainted key taints
everything derived from the array and precision collapses. Where the key is a literal, track it;
where dynamic, fall back to whole-array taint.

## Interprocedural flow

Call-graph-driven, context-sensitive to a bounded depth (default `k = 3` call sites), with
summaries so each function is analysed once per relevant input shape rather than once per path.

Per function, a **summary** records:

```text
FunctionSummary
  fqn
  param_to_return[]      # arg 0 flows to return value
  param_to_param[]       # arg 0 flows into arg 1 (by-reference)
  param_to_sink[]        # arg 0 reaches an SQL sink - makes this function itself a sink
  param_to_property[]    # arg 0 is stored on $this - enables stored-XSS style flows
  sanitizes[]            # arg 0 is cleaned for taint kinds {html, sql}
  returns_tainted        # function is itself a source
```

Summaries are computed bottom-up over the call graph's SCC condensation, so recursion is handled
by fixpoint iteration within a component. They persist in SQLite and survive across runs, which
is most of why incremental scans are fast.

Framework functions get **hand-written summaries** rather than analysed bodies - see
[08-framework-adapters](../08-framework-adapters/README.md). Analysing Laravel's query builder
from source to conclude that `where()` binds parameters is slow, fragile, and unnecessary.

## Precision and its limits

Stated plainly so nobody is surprised:

- **Path-insensitive by default.** If a sanitizer runs only when `$user->isAdmin()`, the join
  treats the value as sanitized on that branch and tainted on the other - correct - but Vigilloo
  will not reason about whether the two branch conditions are mutually satisfiable.
- **Alias analysis is shallow.** Two references to the same object through different variables
  are related only within a function.
- **Dynamic dispatch degrades to unresolved.** `call_user_func($cb, $tainted)` yields a
  low-confidence edge to every candidate; the user can raise the confidence threshold to hide
  these.
- **Container-resolved services** (`app(Foo::class)`, constructor injection) are resolved via
  the container bindings the adapter extracts, not by simulating the container.

Every one of these is reported through edge `confidence`, and confidence propagates into finding
severity. The design goal is not perfect precision; it is **never being wrong about how sure
we are**.

## Output

Data-flow edges land in the graph, and reaching-definition sets plus function summaries are
cached. The taint engine consumes both. Nothing here decides that anything is a vulnerability.
