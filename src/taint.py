"""Taint propagation from route entry points to SQL sinks.

ponytail: statement-order walk, no CFG and no branch sensitivity. Straight-line
controller code is the common case; add a CFG when a fixture needs a sanitizer
applied on only one branch - see docs 05-data-flow-analysis.

ponytail: tracks only the `sql` taint kind as a boolean. The kind set from
docs 06-taint-analysis lands with the second sink class.
"""

from tree_sitter import Node

# Statement kinds that can carry a source, a propagating call or a sink.
# return_statement is not optional: idiomatic Laravel returns the query
# directly, so `return $repo->search($x);` and `return DB::table(...)
# ->orderByRaw(...)` are where the interesting calls actually live. A walk
# over expression_statement alone finds nothing in a typical repository.
from .graph import Project
from .laravel.vocabulary import is_source, sink_arg_index
from .models import PathStep, WalkStats
from .parser import ParsedFile, find_all, node_span, node_text, walk

_STATEMENT_TYPES = ("expression_statement", "return_statement", "echo_statement")


def _giveup(stats: WalkStats | None) -> None:
    """Record one more call site the walk could not follow."""
    if stats is not None:
        stats.unresolved += 1


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
    stats: WalkStats | None = None,
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

    statements = [n for n in walk(method_node) if n.type in _STATEMENT_TYPES]

    for stmt in statements:
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
            else:
                # Reassigned from a clean value: whatever taint the target
                # carried before this statement no longer applies. Without
                # this, `$sort = $request->input('sort'); $sort = 'asc';`
                # would still report $sort as tainted at the sink below.
                local.discard(target)

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

            # Which arguments carry tainted data. Computed before the give-up
            # checks because a give-up only counts as a lost trail when there
            # was something to lose: counting every unresolved receiver fires
            # on benign calls like $request->input() and a ->get() chain
            # terminator, and a counter that reports gaps on correct code
            # trains people to ignore it.
            passed = {i for i, arg in enumerate(args) if _referenced_vars(arg, source) & local}

            # $this->prop->method($tainted) - follow into the callee.
            if not obj.startswith("$this->"):
                if passed:
                    _giveup(stats)
                continue
            prop = obj.removeprefix("$this->")
            target_class = project.resolve_property_type(class_fqn, prop)
            if target_class is None:
                if passed:
                    _giveup(stats)
                continue
            callee_fqn = f"{target_class}::{name}"
            callee = project.method(callee_fqn)
            if callee is None:
                if passed:
                    _giveup(stats)
                continue

            if not passed:
                continue

            callee_tainted = {callee.params[i] for i in passed if i < len(callee.params)}
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
                    project,
                    callee_fqn,
                    callee_tainted,
                    prefix + [step],
                    depth + 1,
                    max_depth,
                    stats,
                )
            )

    return paths


def find_taint_paths(
    project: Project, max_depth: int = 5, stats: WalkStats | None = None
) -> list[list[PathStep]]:
    """Every source-to-sink path reachable from a route entry point."""
    paths: list[list[PathStep]] = []

    for route in project.routes:
        if not route.action_fqn:
            _giveup(stats)
            continue
        entry = PathStep(
            role="entry",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri} -> {route.action_fqn}",
            note="HTTP entry point",
        )
        paths.extend(_walk_method(project, route.action_fqn, set(), [entry], 0, max_depth, stats))

    # Walking nested statements can reach the same call twice, so collapse
    # paths that are step-for-step identical before returning.
    unique: dict[tuple[tuple[str, str, int], ...], list[PathStep]] = {}
    for path in paths:
        key = tuple((s.role, str(s.span.file), s.span.start_line) for s in path)
        unique.setdefault(key, path)

    return sorted(unique.values(), key=lambda p: (str(p[-1].span.file), p[-1].span.start_line))
