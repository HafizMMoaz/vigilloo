"""Taint propagation from route entry points to SQL sinks.

ponytail: statement-order walk, no CFG and no branch sensitivity. Straight-line
controller code is the common case; add a CFG when a fixture needs a sanitizer
applied on only one branch - see docs 05-data-flow-analysis.
"""

from pathlib import Path

from tree_sitter import Node

# Statement kinds that can carry a source, a propagating call or a sink.
# return_statement is not optional: idiomatic Laravel returns the query
# directly, so `return $repo->search($x);` and `return DB::table(...)
# ->orderByRaw(...)` are where the interesting calls actually live. A walk
# over expression_statement alone finds nothing in a typical repository.
from .graph import Project
from .laravel.views import extract_view_bindings, template_path
from .laravel.vocabulary import is_source, sanitizer_clears, sink
from .models import ALL_KINDS, PathStep, TaintKind, WalkStats
from .parser import ParsedFile, find_all, node_span, node_text, walk

_STATEMENT_TYPES = ("expression_statement", "return_statement", "echo_statement")


def _giveup(stats: WalkStats | None) -> None:
    """Record one more call site the walk could not follow."""
    if stats is not None:
        stats.unresolved += 1


def _var_name(node: Node, source: bytes) -> str:
    return node_text(node, source).lstrip("$")


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


def _request_like_params(project: Project, fqn: str) -> frozenset[str]:
    """Parameter names of this method that plausibly hold a Request.

    A parameter counts when its declared type's last namespace segment ends
    with "Request" (Illuminate\\Http\\Request, FormRequest subclasses, ...),
    or when it is literally named $request. The name fallback exists because
    untyped $request parameters are common in the wild and in this repo's own
    fixtures.

    ponytail: a Request parameter that is neither type-hinted nor named
    `request` is missed, and a Request stashed on $this is not tracked.
    Full receiver-type resolution is the upgrade path.
    """
    symbol = project.method(fqn)
    if symbol is None:
        return frozenset()
    names: set[str] = set()
    for param_name, param_type in zip(symbol.params, symbol.param_types, strict=True):
        if param_name == "request":
            names.add(param_name)
        elif param_type is not None and param_type.rsplit("\\", 1)[-1].endswith("Request"):
            names.add(param_name)
    return frozenset(names)


def _is_request_receiver(call: Node, source: bytes, request_vars: frozenset[str]) -> bool:
    """Is the object this source-named method was called on plausibly a Request?

    Source-named methods (get, all, query, only, except, json, url, ...) are
    also Eloquent and Collection methods. Without this check, `Order::where(
    ...)->get()` is indistinguishable from `$request->get(...)` and gets
    reported as attacker-controlled request data - a fabricated evidence path.
    """
    obj = call.child_by_field_name("object")
    if obj is None:
        return False
    if obj.type == "variable_name":
        return _var_name(obj, source) in request_vars
    if obj.type == "function_call_expression":
        return node_text(obj.child_by_field_name("function"), source) == "request"
    return False


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


def _walk_method(
    project: Project,
    fqn: str,
    tainted: dict[str, frozenset[TaintKind]],
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
    local = dict(tainted)
    paths: list[list[PathStep]] = []
    request_vars = _request_like_params(project, fqn)

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
            if any(
                is_source(node_text(c.child_by_field_name("name"), source))
                and _is_request_receiver(c, source, request_vars)
                for c in calls
            ):
                local[target] = ALL_KINDS
                prefix = prefix + [
                    PathStep(
                        role="source",
                        span=node_span(assign, parsed.path),
                        snippet=node_text(assign, source).strip(),
                        note="attacker-controlled request data",
                    )
                ]
                continue

            kinds = expr_kinds(right, source, local)
            if kinds:
                local[target] = kinds
            else:
                # Reassigned from a clean or fully sanitized value: whatever
                # taint the target carried before this statement no longer
                # applies. Without this, `$sort = $request->input('sort');
                # $sort = 'asc';` would still report $sort as tainted below.
                local.pop(target, None)

        # 2. Calls: either a sink, or a step deeper into another method.
        for call in find_all(stmt, "member_call_expression"):
            obj, name, args = _call_parts(call, source)

            sink_found = sink(name)
            if sink_found is not None:
                index, kind = sink_found
                if index < len(args) and kind in expr_kinds(args[index], source, local):
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

            # Which arguments carry tainted data, and which kinds. Computed
            # before the give-up checks because a give-up only counts as a lost
            # trail when there was something to lose: counting every unresolved
            # receiver fires on benign calls like $request->input() and a
            # ->get() chain terminator, and a counter that reports gaps on
            # correct code trains people to ignore it.
            passed = {
                i: kinds for i, arg in enumerate(args) if (kinds := expr_kinds(arg, source, local))
            }

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

            callee_tainted = {
                callee.params[i]: kinds for i, kinds in passed.items() if i < len(callee.params)
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
                    project,
                    callee_fqn,
                    callee_tainted,
                    prefix + [step],
                    depth + 1,
                    max_depth,
                    stats,
                )
            )

        # 3. view() hands data to a template, where html taint can reach a
        #    raw echo. A statement can hold more than one view() call, as in a
        #    ternary choosing between two templates, so each is walked.
        for binding in extract_view_bindings(stmt, source):
            bound: dict[str, frozenset[TaintKind]] = {}
            for name, expression in binding.variables:
                kinds = expr_kinds(expression, source, local)
                if kinds:
                    bound[name] = kinds
            for name in binding.compacted:
                kinds = local.get(name, frozenset())
                if kinds:
                    bound[name] = kinds

            if not bound:
                continue

            # binding.template is None when the name could not be resolved to
            # a literal (extract_view_bindings still returns the call rather
            # than dropping it, see laravel/views.py). That case falls into
            # the same unresolved path below as a name that resolved to a
            # file outside the project.
            template = template_path(binding.template) if binding.template is not None else None
            if template is None or template not in project.blade:
                # A template that was handed tainted data and could not be
                # resolved is a real gap in coverage, and invariant 4 says
                # gaps are reported rather than hidden.
                _giveup(stats)
                continue

            step = PathStep(
                role="propagator",
                span=node_span(stmt, parsed.path),
                snippet=node_text(stmt, source).strip(),
                note=f"view data into {template}",
            )
            paths.extend(_walk_template(project, template, bound, prefix + [step]))

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
        paths.extend(_walk_method(project, route.action_fqn, {}, [entry], 0, max_depth, stats))

    # Walking nested statements can reach the same call twice, so collapse
    # paths that are step-for-step identical before returning.
    unique: dict[tuple[tuple[str, str, int], ...], list[PathStep]] = {}
    for path in paths:
        key = tuple((s.role, str(s.span.file), s.span.start_line) for s in path)
        unique.setdefault(key, path)

    return sorted(unique.values(), key=lambda p: (str(p[-1].span.file), p[-1].span.start_line))
