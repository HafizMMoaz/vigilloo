"""Taint propagation from route entry points to SQL sinks.

ponytail: statement-order walk, no CFG and no branch sensitivity. Straight-line
controller code is the common case; add a CFG when a fixture needs a sanitizer
applied on only one branch - see docs 05-data-flow-analysis.
"""

from collections.abc import Callable
from pathlib import Path

from tree_sitter import Node

from .analysis.cfg import BasicBlock, CFGBuilder
from .analysis.ssa import PhiNode, SSABuilder, SSAValue

# Statement kinds that can carry a source, a propagating call or a sink.
# return_statement is not optional: idiomatic Laravel returns the query
# directly, so `return $repo->search($x);` and `return DB::table(...)
# ->orderByRaw(...)` are where the interesting calls actually live. A walk
# over expression_statement alone finds nothing in a typical repository.
from .graph import Project
from .laravel.facades import resolve_facade
from .laravel.middleware import authenticated_by
from .laravel.models import Protection, model_config
from .laravel.routes import uri_params
from .laravel.views import extract_view_bindings, template_path
from .laravel.vocabulary import (
    CODE_EXECUTION_RULE,
    COMMAND_INJECTION_RULE,
    LARAVEL_BLADE_RAW_ECHO_RULE,
    MAGIC_PROPERTY_KINDS,
    MASS_ASSIGNMENT_RULE,
    ROUTE_PARAM_KINDS,
    XSS_RULE,
    eloquent_write,
    input_facade_kinds,
    is_anti_sanitizer,
    is_request_helper,
    is_source,
    is_superglobal,
    route_param_is_source,
    sanitizer_clears,
    sink_arg_name,
    sinks,
    source_kinds,
    static_sinks,
    superglobal_kinds,
)
from .models import PathStep, Route, TaintKind, WalkStats
from .parser import ParsedFile, find_all, find_any, node_span, node_text

_STATEMENT_TYPES = ("expression_statement", "return_statement", "echo_statement")

# `$request->input('x')` and `$request?->input('x')` read the same value from the
# same object. The nullsafe operator decides what happens when the receiver is
# null; it says nothing about where the value came from, so every branch that
# recognises one form has to recognise the other. tree-sitter spells them as two
# node types, which is the entire reason this constant exists: a walk keyed on
# the arrow form alone is silently blind to modern code, and a missed source is
# a false negative that no part of the report mentions.
_MEMBER_CALLS = ("member_call_expression", "nullsafe_member_call_expression")
_MEMBER_ACCESSES = ("member_access_expression", "nullsafe_member_access_expression")


# Resolves a class name as written at a call site to its FQN, or None when the file's
# imports and namespace do not settle it. Passed in rather than reached for, because
# expr_kinds is also called from the Blade walk and from property tests that have no
# Project - and because a source that fired on the *spelling* `Input` would report every
# project that happens to name a class that.
ClassResolver = Callable[[str], str | None]

# A template handed tainted data whose original text contains one of these is
# a gap the walk cannot see past - see _walk_template.


def _giveup(stats: WalkStats | None) -> None:
    """Record one more call site the walk could not follow."""
    if stats is not None:
        stats.unresolved += 1


def _followed(stats: WalkStats | None) -> None:
    """Record one more call site the walk did follow.

    Every _giveup below has one of these as its opposite branch, because the
    give-ups alone are a numerator with no denominator: "eleven unresolved" is
    a catastrophe in a project with twelve call sites and a rounding error in
    one with four thousand.
    """
    if stats is not None:
        stats.resolved += 1


def _var_name(node: Node, source: bytes) -> str:
    return node_text(node, source).lstrip("$")


def _literal_key(node: Node, source: bytes) -> str | None:
    """The text of a literal subscript, or None when the key is not a literal.

    `$_SERVER['HTTP_HOST']` has to be told apart from `$_SERVER[$name]`: the first
    states which key is read and the second does not. An interpolated
    `"{$prefix}_HOST"` is not a literal either - what it evaluates to is not knowable
    here, and reading it as the text that happens to be written would be a guess.
    """
    if node.type == "string":
        content = next((c for c in node.named_children if c.type == "string_content"), None)
        return node_text(content, source) if content is not None else ""
    if node.type == "encapsed_string" and all(
        c.type == "string_content" for c in node.named_children
    ):
        return "".join(node_text(c, source) for c in node.named_children)
    return None


def _superglobal_read(node: Node, source: bytes) -> tuple[str, str | None] | None:
    """`(name, key)` when this node reads a superglobal, else None.

    Both forms the grammar produces are handled: a bare `$_POST`, and a subscript
    `$_POST['x']`. tree-sitter-php gives `subscript_expression` no `object` or `index`
    field, so the base is the first named child and the key the second - see the
    dump_ast note in CLAUDE.md.
    """
    if node.type == "subscript_expression":
        children = node.named_children
        if not children or children[0].type != "variable_name":
            return None
        name = _var_name(children[0], source)
        if not is_superglobal(name):
            return None
        return name, (_literal_key(children[1], source) if len(children) > 1 else None)
    if node.type == "variable_name":
        name = _var_name(node, source)
        return (name, None) if is_superglobal(name) else None
    return None


def _argument_count(call: Node) -> int:
    """How many arguments a call node was given.

    `request()` and `request('sort')` are different sources: the first returns the
    Request object and is already handled as a receiver, the second returns a value off
    the wire.
    """
    args = call.child_by_field_name("arguments")
    if args is None:
        return 0
    return sum(1 for child in args.children if child.type == "argument")


def _get_first_string_arg(args_node: Node | None, source: bytes) -> str | None:
    if args_node is None:
        return None
    real_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
    if real_args:
        text = node_text(real_args[0], source).strip()
        return text.strip("'\"")
    return None


class LocalState:
    def __init__(
        self,
        linear_state: dict[str, frozenset[TaintKind]],
        get_node_taint: Callable[[str, Node], frozenset[TaintKind]] | None = None,
        project: Project | None = None,
        local_types: dict[str, str] | None = None,
    ):
        self.linear_state = linear_state
        self.get_node_taint = get_node_taint
        self.project = project
        self.local_types = local_types

    def get(self, name: str, default: frozenset[TaintKind] = frozenset()) -> frozenset[TaintKind]:
        return self.linear_state.get(name, default)

    def get_node(self, name: str, node: Node) -> frozenset[TaintKind]:
        if self.get_node_taint:
            return self.get_node_taint(name, node)
        return self.linear_state.get(name, frozenset())


def _union_of_children(
    node: Node,
    source: bytes,
    local: LocalState,
    request_vars: frozenset[str],
    resolve: ClassResolver | None = None,
    validated_fields: dict[str, frozenset[TaintKind]] | None = None,
) -> frozenset[TaintKind]:
    kinds: frozenset[TaintKind] = frozenset()
    for child in node.children:
        kinds |= expr_kinds(child, source, local, request_vars, resolve, validated_fields)
    return kinds


def _get_local(local: LocalState, name: str, node: Node) -> frozenset[TaintKind]:
    return local.get_node(name, node)


def expr_kinds(
    node: Node,
    source: bytes,
    local: LocalState,
    request_vars: frozenset[str] = frozenset(),
    resolve: ClassResolver | None = None,
    validated_fields: dict[str, frozenset[TaintKind]] | None = None,
) -> frozenset[TaintKind]:
    """Which taint kinds are still live in the value this expression produces.

    Replaces slice 1's "does this expression mention a tainted variable", which
    could not express sanitizing: e($x) mentions $x, so a flat membership test
    sees taint no matter what wraps it.

    Sources are recognised here rather than only at assignment, so an inline
    `User::create($request->all())` or `whereRaw($request->input('sort'))` is
    seen at all. Recognising them only where they were stored in a variable
    made the single most idiomatic form of both calls invisible.

    The default case is a union over children, so an unrecognised construct
    preserves taint rather than dropping it. Silently losing taint is a false
    negative, and a security tool that under-reports without saying so is worse
    than one that over-reports.
    """
    # A superglobal read, bare or subscripted. Checked ahead of the local-variable
    # branch because a superglobal is never in `local`: no statement assigned it, PHP
    # populated it before the first line ran, so looking it up in the local state finds
    # nothing and the read looks clean.
    superglobal = _superglobal_read(node, source)
    if superglobal is not None:
        # Decisive even when it returns no kinds. Falling through to the union over
        # children would reach the bare `$_SERVER` under `$_SERVER['DOCUMENT_ROOT']`,
        # which is tainted because the array holds the attacker-controlled keys, and
        # that would taint the one key the spec calls safe by way of its container.
        return superglobal_kinds(*superglobal)

    if node.type == "variable_name":
        return _get_local(local, _var_name(node, source), node)

    if node.type in _MEMBER_CALLS:
        name = node_text(node.child_by_field_name("name"), source)
        custom_entering: frozenset[TaintKind] = frozenset()
        custom_cleared: frozenset[TaintKind] = frozenset()

        obj = node.child_by_field_name("object")
        if obj is not None and local.project and local.local_types:
            obj_text = _var_name(obj, source)
            if obj_text in local.local_types:
                obj_type = local.local_types[obj_text]
                if (obj_type, name) in local.project.custom_sources:
                    custom_entering = frozenset(local.project.custom_sources[(obj_type, name)])
                if (obj_type, name) in local.project.custom_sanitizers:
                    custom_cleared = frozenset(local.project.custom_sanitizers[(obj_type, name)])

        if custom_cleared:
            args = node.child_by_field_name("arguments")
            inner = (
                _union_of_children(args, source, local, request_vars, resolve, validated_fields)
                if args is not None
                else frozenset()
            )
            inner = inner - custom_cleared
            if custom_entering:
                return inner | custom_entering
            return inner

        entering = source_kinds(name)
        if (entering and _is_request_receiver(node, source, request_vars)) or custom_entering:
            entering = entering | custom_entering
            if validated_fields and name in ("input", "get", "query", "post", "string"):
                args = node.child_by_field_name("arguments")
                field_name = _get_first_string_arg(args, source)
                if field_name and field_name in validated_fields:
                    return entering - validated_fields[field_name]
            return entering

    # `$request->bio`, the magic property form of `$request->input('bio')`. Decisive
    # like the superglobal branch above, and for the same reason: falling through to the
    # union over children would reach the bare `$request` underneath, which carries
    # nothing, so the read would look clean. The receiver check is what stops this
    # tainting every property fetch in the project.
    if node.type in _MEMBER_ACCESSES and _is_request_receiver(node, source, request_vars):
        prop_name = node_text(node.child_by_field_name("name"), source)
        if validated_fields and prop_name in validated_fields:
            return MAGIC_PROPERTY_KINDS - validated_fields[prop_name]
        return MAGIC_PROPERTY_KINDS

    if node.type == "subscript_expression":
        index_node = node.child_by_field_name("index")
        if index_node is not None and validated_fields:
            field_name = node_text(index_node, source).strip("'\"")
            if field_name in validated_fields:
                cleared = validated_fields[field_name]
                inner = _union_of_children(
                    node, source, local, request_vars, resolve, validated_fields
                )
                return inner - cleared

    if node.type == "function_call_expression":
        name = node_text(node.child_by_field_name("function"), source)
        # `request('sort')`, the function form of `$request->input('sort')`. Decisive,
        # like the superglobal and magic-property branches: the argument underneath is a
        # literal key carrying nothing, so falling through would read as clean.
        if is_request_helper(name, _argument_count(node)):
            entering = source_kinds("input")
            if validated_fields:
                args = node.child_by_field_name("arguments")
                field_name = _get_first_string_arg(args, source)
                if field_name and field_name in validated_fields:
                    return entering - validated_fields[field_name]
            return entering
        cleared = sanitizer_clears(name)
        if local.project:
            func_fqn = name.lstrip("\\")
            if (func_fqn, "") in local.project.custom_sanitizers:
                custom_clears = frozenset(local.project.custom_sanitizers[(func_fqn, "")])
                if cleared:
                    cleared = cleared | custom_clears
                else:
                    cleared = custom_clears

        if name == "json_encode":
            args_node = node.child_by_field_name("arguments")
            if args_node and "JSON_HEX_TAG" in node_text(args_node, source):
                if cleared:
                    cleared = cleared | frozenset({TaintKind.JS, TaintKind.HTML})
                else:
                    cleared = frozenset({TaintKind.JS, TaintKind.HTML})
        if cleared:
            args = node.child_by_field_name("arguments")
            inner = (
                _union_of_children(args, source, local, request_vars, resolve, validated_fields)
                if args is not None
                else frozenset()
            )
            return inner - cleared

    # `Input::get('sort')`, the facade Laravel removed in 6.0. Keyed on the resolved
    # class, so a project's own `Input` is untouched - the same reason the DB facade
    # sinks require a resolved receiver.
    if node.type == "scoped_call_expression":
        scope = node.child_by_field_name("scope")
        name_node = node.child_by_field_name("name")
        if scope is not None and name_node is not None:
            scope_text = node_text(scope, source)
            method_text = node_text(name_node, source)

            if method_text == "from" and (
                scope_text == "Js" or (resolve and resolve(scope_text) == "Illuminate\\Support\\Js")
            ):
                args = node.child_by_field_name("arguments")
                inner = (
                    _union_of_children(args, source, local, request_vars, resolve, validated_fields)
                    if args is not None
                    else frozenset()
                )
                return inner - frozenset({TaintKind.JS, TaintKind.HTML})

            if resolve is not None:
                scope_fqn = resolve(scope_text)
                if (
                    local.project
                    and scope_fqn
                    and (scope_fqn, method_text) in local.project.custom_sanitizers
                ):
                    cleared = frozenset(local.project.custom_sanitizers[(scope_fqn, method_text)])
                    if cleared:
                        args = node.child_by_field_name("arguments")
                        inner = (
                            _union_of_children(
                                args, source, local, request_vars, resolve, validated_fields
                            )
                            if args is not None
                            else frozenset()
                        )
                        return inner - cleared

                if (
                    local.project
                    and scope_fqn
                    and (scope_fqn, method_text) in local.project.custom_sources
                ):
                    entering = frozenset(local.project.custom_sources[(scope_fqn, method_text)])
                    if entering:
                        if validated_fields:
                            args = node.child_by_field_name("arguments")
                            field_name = _get_first_string_arg(args, source)
                            if field_name and field_name in validated_fields:
                                return entering - validated_fields[field_name]
                        return entering

                entering = input_facade_kinds(scope_fqn, method_text)
                if entering:
                    if validated_fields:
                        args = node.child_by_field_name("arguments")
                        field_name = _get_first_string_arg(args, source)
                        if field_name and field_name in validated_fields:
                            return entering - validated_fields[field_name]
                    return entering

    if node.type == "cast_expression":
        # cast_type text is "int", without the parentheses.
        cast = node_text(node.child_by_field_name("type"), source).strip().lower()
        if cast in ("int", "integer", "float", "double"):
            value = node.child_by_field_name("value")
            inner = (
                expr_kinds(value, source, local, request_vars, resolve, validated_fields)
                if value is not None
                else frozenset()
            )
            return inner - {TaintKind.SQL, TaintKind.HTML}

    return _union_of_children(node, source, local, request_vars, resolve, validated_fields)


def _request_like_params(project: Project, fqn: str, route: Route | None = None) -> frozenset[str]:
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

    route_params: set[str] = set()
    if route is not None:
        route_params = set(uri_params(route.uri))

    names: set[str] = set()
    for param_name, param_type in zip(symbol.params, symbol.param_types, strict=True):
        if param_name == "request":
            names.add(param_name)
        elif param_type is not None and param_type.rsplit("\\", 1)[-1].endswith("Request"):
            names.add(param_name)
        elif not param_type and param_name not in route_params and route is not None:
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


def _source_note(
    node: Node,
    source: bytes,
    request_vars: frozenset[str],
    resolve: ClassResolver | None = None,
    local: LocalState | None = None,
) -> str | None:
    """How this expression reads attacker-controlled data, or None if it does not.

    The return value is the evidence step's note, so the step names *which* source was
    crossed and not merely that one was. `$_SERVER['HTTP_HOST']` and
    `$request->input('x')` are both request data, and a developer following the path has
    to know which of them to go and look at.

    Pre-order, first crossing wins. A step describes one crossing, and picking whichever
    of several the walk happened to reach first would make the path depend on iteration
    order, which invariant 8 forbids.
    """
    superglobal = _superglobal_read(node, source)
    if superglobal is not None:
        if superglobal_kinds(*superglobal):
            return f"attacker-controlled ${superglobal[0]}"
        # A superglobal read carrying nothing is `$_SERVER['DOCUMENT_ROOT']`, and the
        # bare `$_SERVER` underneath it is not a source in its own right here. Stopping
        # rather than descending is what keeps the safe key safe, for the same reason
        # expr_kinds is decisive above.
        if node.type == "subscript_expression":
            return None
    if node.type in _MEMBER_CALLS:
        name = node_text(node.child_by_field_name("name"), source)
        if local and local.project and local.local_types:
            obj = node.child_by_field_name("object")
            if obj is not None:
                obj_text = _var_name(obj, source)
                if obj_text in local.local_types:
                    obj_type = local.local_types[obj_text]
                    if (obj_type, name) in local.project.custom_sources:
                        return (
                            f"attacker-controlled data, read through custom source "
                            f"{obj_type}::{name}"
                        )

        if is_source(name) and _is_request_receiver(node, source, request_vars):
            return "attacker-controlled request data"
    if node.type in _MEMBER_ACCESSES and _is_request_receiver(node, source, request_vars):
        # Named apart from the method form deliberately. A developer sent to
        # "request data" goes looking for a call and finds a property, and the
        # entire point of this source is that the property form does not look
        # like one.
        return "attacker-controlled request data, read as a magic property"
    if node.type == "function_call_expression" and is_request_helper(
        node_text(node.child_by_field_name("function"), source), _argument_count(node)
    ):
        # Named for the helper rather than folded into "request data", because the
        # developer following this path is looking for a function call in a method that
        # very often has no $request parameter at all.
        return "attacker-controlled request data, read through the request() helper"
    if node.type == "scoped_call_expression" and resolve is not None:
        scope = node.child_by_field_name("scope")
        name_node = node.child_by_field_name("name")
        if scope is not None and name_node is not None:
            scope_fqn = resolve(node_text(scope, source))
            method_text = node_text(name_node, source)

            if (
                local
                and local.project
                and scope_fqn
                and (scope_fqn, method_text) in local.project.custom_sources
            ):
                return (
                    f"attacker-controlled data, read through custom source "
                    f"{scope_fqn}::{method_text}"
                )

            if input_facade_kinds(scope_fqn, method_text):
                return "attacker-controlled request data, read through the legacy Input facade"
    for child in node.children:
        note = _source_note(child, source, request_vars, resolve, local)
        if note is not None:
            return note
    return None


def _inline_source_steps(
    arg: Node,
    parsed: ParsedFile,
    request_vars: frozenset[str],
    resolve: ClassResolver | None = None,
    local: LocalState | None = None,
) -> list[PathStep]:
    """The source step for a sink argument that reads the Request directly.

    `User::create($request->all())` never assigns the source to a variable, so
    nothing in the statement loop emits a source step for it. Without this the
    path jumps from the route to the sink and never says where the data
    entered, which is exactly the gap invariant 2 exists to prevent.
    """
    note = _source_note(arg, parsed.source, request_vars, resolve, local)
    if note is None:
        return []
    return [
        PathStep(
            role="source",
            span=node_span(arg, parsed.path),
            snippet=node_text(arg, parsed.source).strip(),
            note=note,
        )
    ]


def _constructed_class(node: Node, source: bytes, project: Project, file: Path) -> str | None:
    """The class a `new Foo(...)` or `Foo::bar(...)` expression yields, if any.

    Deliberately shallow: it does not try to know that `find()` returns a model
    while `count()` returns an integer. A wrong class here can only cause a
    miss, because the sink additionally requires the class to be a model and
    the argument to carry mass_assign taint.
    """
    if node.type == "object_creation_expression":
        for child in node.children:
            if child.type in ("name", "qualified_name"):
                return project.resolve_class_name(file, node_text(child, source))
        return None
    if node.type == "scoped_call_expression":
        scope = node.child_by_field_name("scope")
        if scope is not None and scope.type in ("name", "qualified_name"):
            scope_name = node_text(scope, source)
            # `App::make(...)`
            if scope_name == "App":
                name_node = node.child_by_field_name("name")
                if name_node and node_text(name_node, source) == "make":
                    args = node.child_by_field_name("arguments")
                    if args:
                        first_arg = next(
                            (c for c in args.named_children if c.type == "argument"), None
                        )
                        if first_arg and first_arg.children:
                            expr = first_arg.children[0]
                            if expr.type == "class_constant_access_expression":
                                cls_node = expr.children[0]
                                if cls_node:
                                    return project.resolve_class_name(
                                        file, node_text(cls_node, source)
                                    )
            return project.resolve_class_name(file, scope_name)
    if node.type == "function_call_expression":
        # `app(...)` or `resolve(...)`
        name_node = node.child_by_field_name("function")
        if name_node and node_text(name_node, source) in ("app", "resolve"):
            args = node.child_by_field_name("arguments")
            if args:
                first_arg = next((c for c in args.named_children if c.type == "argument"), None)
                if first_arg and first_arg.children:
                    expr = first_arg.children[0]
                    if expr.type == "class_constant_access_expression":
                        cls_node = expr.children[0]
                        if cls_node:
                            return project.resolve_class_name(file, node_text(cls_node, source))
                    elif expr.type == "string":
                        val = node_text(expr, source)
                        if val.startswith("'") and val.endswith("'"):
                            val = val[1:-1].replace("\\\\", "\\")
                        elif val.startswith('"') and val.endswith('"'):
                            val = val[1:-1].replace("\\\\", "\\")
                        # Return string binding (could be an FQN or just an alias like 'reports')
                        if val:
                            return val

    return None


def _mass_assign_steps(
    project: Project,
    call: Node,
    method: str,
    args: list[Node],
    receiver_fqn: str | None,
    parsed: ParsedFile,
    local: LocalState,
    request_vars: frozenset[str],
    resolve: ClassResolver | None = None,
) -> list[PathStep] | None:
    """The model and sink steps for an Eloquent array write, if it is unsafe.

    Three-way result, and the distinction matters to the coverage counter:

    - None: not an Eloquent write on a class this walk knows. The caller falls
      through to its propagator handling, which may record a lost trail.
    - []: a write this walk fully resolved and judged safe. The caller stops,
      and records nothing, because nothing was lost. Counting a call whose
      receiver, model configuration and argument kinds were all read as an
      unresolved gap would report gaps on correct code, which is how a
      coverage counter becomes something people ignore.
    - steps: the finding.
    """
    write = eloquent_write(method)
    if write is None or receiver_fqn is None:
        return None
    config = model_config(project.classes, receiver_fqn, schema=getattr(project, "schema", None))
    if config is None:
        return None

    index, bypasses_protection = write
    if index >= len(args):
        return []
    if TaintKind.MASS_ASSIGN not in expr_kinds(
        args[index], parsed.source, local, request_vars, resolve
    ):
        return []
    if config.protection is Protection.GUARDED and not bypasses_protection:
        return []

    if bypasses_protection:
        note = f"{method}() bypasses both $fillable and $guarded"
        model_span = project.classes[receiver_fqn].span
    elif config.protection is Protection.PRIVILEGED_FILLABLE:
        note = f"$fillable allows the privileged column {config.privileged_column}"
        model_span = config.reason_span or project.classes[receiver_fqn].span
    else:
        note = "$guarded = [] - mass assignment protection disabled"
        model_span = config.reason_span or project.classes[receiver_fqn].span

    return [
        *_inline_source_steps(args[index], parsed, request_vars, resolve),
        PathStep(
            role="model",
            span=model_span,
            snippet=receiver_fqn,
            note=note,
        ),
        PathStep(
            role="sink",
            span=node_span(call, parsed.path),
            snippet=node_text(call, parsed.source).strip(),
            note=f"request-supplied array written to {receiver_fqn.rsplit('\\', 1)[-1]}",
            rule_id=MASS_ASSIGNMENT_RULE,
        ),
    ]


def _call_parts(call: Node, source: bytes) -> tuple[str, str, list[Node]]:
    """Return (receiver text, method name, argument nodes) for a call node."""
    obj = node_text(call.child_by_field_name("object"), source)
    name = node_text(call.child_by_field_name("name"), source)
    args_node = call.child_by_field_name("arguments")
    args: list[Node] = []
    if args_node is not None:
        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
    return obj, name, args


def _scoped_parts(call: Node, source: bytes) -> tuple[str, str, list[Node]] | None:
    """Return (scope text, method name, argument nodes) for `Foo::bar(...)`.

    The scoped counterpart of `_call_parts`. Returns None rather than empty strings when the
    grammar did not give a scope or a name, because a scoped call missing either is a parse
    artefact and treating it as a call to `""` would look up a sink under the empty name.
    """
    scope_node = call.child_by_field_name("scope")
    name_node = call.child_by_field_name("name")
    if scope_node is None or name_node is None:
        return None
    args_node = call.child_by_field_name("arguments")
    args: list[Node] = []
    if args_node is not None:
        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
    return node_text(scope_node, source), node_text(name_node, source), args


def _scoped_receiver(
    project: Project, written: str, lexical_fqn: str, runtime_fqn: str, file: Path
) -> str | None:
    """The class a scoped call's left-hand side names.

    `self` and `static` are the enclosing class and `parent` is its base, none of which
    `resolve_class_name` can know - it resolves names against a namespace and an import table,
    and these three are resolved against the class the call is written inside. Without this a
    `self::helper($tainted)` resolves to a class literally named `self`, finds no method, and is
    counted as an unresolved call on code that is perfectly resolvable.

    `self` and `static` are not the same thing and are not treated as such. In a class body
    `self::` is bound where the code was written, so it stays on `lexical_fqn`: an inherited
    method's `self::helper()` runs the ancestor's helper, not a subclass's. `static::` is late
    static binding - it names the class the call was made on - so it follows `runtime_fqn` and
    reaches an override, which is the one PHP would run.

    Inside a *trait*, `self` is the consuming class and not the trait, because PHP composes a
    trait's body into whatever used it. `parent::` follows the same rule for the same reason: a
    trait has no parent of its own, so it climbs from the class that composed it.
    """
    if written in ("self", "static"):
        if written == "static" or lexical_fqn in project.traits:
            return runtime_fqn
        return lexical_fqn
    if written == "parent":
        owner = lexical_fqn if lexical_fqn in project.classes else runtime_fqn
        info = project.classes.get(owner)
        return info.parent if info else None

    fqn = project.resolve_class_name(file, written)
    if fqn:
        facade_concrete = resolve_facade(fqn, project)
        if facade_concrete:
            return facade_concrete

        # An unknown built-in facade cannot be traced and has no known concrete class.
        # Returning None forces `stats.unresolved += 1` in `_walk_method`.
        if fqn.startswith("Illuminate\\Support\\Facades\\"):
            return None

    return fqn


def _argument_name(arg: Node, source: bytes) -> str | None:
    """The name a named argument was passed under, or None when it is positional.

    tree-sitter gives an `argument` node a `name` field only when the call site wrote
    one, so this is the whole test. The value is the node's remaining child, which
    `_sink_argument` reads rather than the argument wrapper - the wrapper's text is
    `sql: $x`, and taking that as the expression would put the parameter name into the
    evidence snippet.
    """
    name = arg.child_by_field_name("name")
    return node_text(name, source) if name is not None else None


def _sink_argument(args: list[Node], index: int, param: str | None, source: bytes) -> Node | None:
    """The argument a sink's dangerous parameter actually received, or None if absent.

    Position is how PHP binds an argument only until a name is written. Once the call
    site says `whereRaw(bindings: [], sql: $x)`, position 0 holds the empty bindings
    array and the injectable SQL is at position 1, so an index-only lookup is wrong in
    both directions at once: it loses that injection, and on the mirror image
    `whereRaw(bindings: [$x], sql: 'a = ?')` it reads the binding and reports a
    parameterised call that is perfectly safe.

    The name wins whenever it appears, and the index is the fallback - which is PHP's
    own rule, not a heuristic. A sink whose parameter name this module does not know
    (`param` is None) keeps the old behaviour exactly.

    Named arguments may follow positional ones, so the index fallback counts only the
    positional arguments rather than indexing the list. `f($sql, bindings: [])` binds
    `$sql` to parameter 0 because it is the first *positional* argument, and a list
    index happens to agree here only because nothing precedes it.
    """
    if param is not None:
        for arg in args:
            if _argument_name(arg, source) == param:
                return arg
    positional = [arg for arg in args if _argument_name(arg, source) is None]
    if index >= len(positional):
        return None
    return positional[index]


def _sink_steps(
    call: Node,
    args: list[Node],
    found: tuple[int, TaintKind, str],
    parsed: ParsedFile,
    method: str,
    local: LocalState,
    request_vars: frozenset[str],
    resolve: ClassResolver | None = None,
    validated_fields: dict[str, frozenset[TaintKind]] | None = None,
) -> list[PathStep]:
    """The evidence steps for a call that reached a sink, or [] if the taint does not reach it.

    Shared by the member-call and scoped-call branches of the walk. Argument precision is the
    whole point and it is easy to lose by duplicating: `whereRaw('age > ?', [$age])` is safe and
    `whereRaw("age > $age")` is not, so the rule is about *which* argument carries the kind, and
    two copies of that check are two chances for one of them to drift into flagging the call.
    """
    index, kind, rule_id = found
    argument = _sink_argument(args, index, sink_arg_name(method), parsed.source)
    if argument is None:
        return []
    # `Process::run(['cmd', $arg])` array form does not go through a shell and
    # must not fire. The argument node is wrapped in an "argument" container, so
    # unwrap it to check the inner expression type.
    if kind == TaintKind.SHELL:
        inner = argument
        if inner.type == "argument":
            inner = next(
                (c for c in inner.children if c.type not in (",", "name", ":")),
                inner,
            )
        if inner.type == "array_creation_expression":
            return []
    if kind not in expr_kinds(
        argument, parsed.source, local, request_vars, resolve, validated_fields
    ):
        return []
    note = "shell command execution" if kind == TaintKind.SHELL else "unparameterised SQL fragment"
    return _inline_source_steps(argument, parsed, request_vars, resolve) + [
        PathStep(
            role="sink",
            span=node_span(call, parsed.path),
            snippet=node_text(call, parsed.source).strip(),
            note=note,
            rule_id=rule_id,
        )
    ]


def _follow_static(
    project: Project,
    call: Node,
    receiver_fqn: str | None,
    name: str,
    args: list[Node],
    parsed: ParsedFile,
    local: LocalState,
    request_vars: frozenset[str],
    prefix: list[PathStep],
    depth: int,
    max_depth: int,
    stats: WalkStats | None,
    resolve: ClassResolver | None = None,
    visited: frozenset[tuple[str, frozenset[tuple[str, frozenset[TaintKind]]]]] | None = None,
) -> list[list[PathStep]]:
    """Walk into `Receiver::method(...)` when it is a method of a class in this project.

    A static call is the easiest interprocedural edge there is - the class is written at the
    call site, so unlike `$service->handle()` there is no receiver to infer - and until now the
    walk followed none of them. Tainted data passed to a project's own helper simply stopped,
    silently, which is the failure mode invariant 4 exists to make visible.

    Gives up only when something was actually being carried, matching the member-call branch,
    and only when the receiver is a class this project contains. Those two conditions are
    different and the second is the subtle one.

    A call whose target lives outside the project - `Carbon::parse($x)`, `Cache::get($key)`,
    and `Post::find($id)` where `Post` is ours but `find` is Eloquent's - is not a resolution
    failure. `load_project` excludes `vendor/` by design, so the engine has never seen that
    code and no amount of better name resolution will reach it: it is the boundary of what
    v0.1 analyses, not a measure of how well it analysed. Counting each one would subtract from
    the resolution rate in proportion to how much framework a project uses, making an idiomatic
    Laravel application score worse than a bare one and reporting the engine's own design as a
    defect on every scan, permanently. docs/22-testing wants that rate to move when false
    negatives are about to appear, and a number that never reaches 100% on any real project
    cannot do that.

    `Project.ancestry` is what tells the two apart, and the distinction is finer than "is the
    receiver ours". `App\\Models\\Post` is a project class and `Post::find` still resolves into
    the framework, because the chain leaves the project at `extends Model`. A method missing from
    a chain that stays *inside* the project is the real gap: the code is here and the walk failed
    to reach it. Inherited and trait-provided methods now resolve, so what remains is genuinely
    absent or ambiguous and is counted rather than guessed.
    """
    passed = {
        i: kinds
        for i, arg in enumerate(args)
        if (kinds := expr_kinds(arg, parsed.source, local, request_vars, resolve))
    }

    if receiver_fqn is None:
        if passed:
            _giveup(stats)
        return []

    callee_fqn = f"{receiver_fqn}::{name}"
    callee = project.method(callee_fqn)
    if callee is None:
        _, complete = project.ancestry(receiver_fqn)
        if passed and complete:
            _giveup(stats)
        return []
    if not passed:
        return []

    _followed(stats)
    callee_tainted = {
        callee.params[i]: kinds for i, kinds in passed.items() if i < len(callee.params)
    }
    if not callee_tainted:
        return []

    step = PathStep(
        role="propagator",
        span=node_span(call, parsed.path),
        snippet=node_text(call, parsed.source).strip(),
        note=f"argument {min(passed)} into {callee.fqn}",
    )
    inner_paths = _walk_method(
        project,
        callee_fqn,
        callee_tainted,
        [],
        depth + 1,
        max_depth,
        stats,
        receiver_fqn,
        visited=visited,
    )
    return [prefix + [step] + p for p in inner_paths]


def _extract_foreach_vars(stmt: Node, source: bytes) -> tuple[Node | None, list[str]]:
    """(collection_expr_node, [loop_var_names]) for a foreach_statement."""
    children = [c for c in stmt.children if c.type not in ("(", ")", "foreach")]
    as_idx = -1
    for i, c in enumerate(children):
        if c.type == "as" or node_text(c, source) == "as":
            as_idx = i
            break
    if as_idx <= 0:
        return None, []

    collection_node = children[as_idx - 1]
    loop_vars: list[str] = []
    for c in children[as_idx + 1 :]:
        if c.type in (":", ";", "compound_statement", "colon"):
            break
        for var_node in find_all(c, "variable_name"):
            v_name = _var_name(var_node, source)
            if v_name:
                loop_vars.append(v_name)
    return collection_node, loop_vars


def _walk_template(
    project: Project,
    template: Path,
    bound: dict[str, frozenset[TaintKind]],
    prefix: list[PathStep],
    stats: WalkStats | None = None,
    visited: set[Path] | None = None,
) -> list[list[PathStep]]:
    """Every raw echo in this template (or included/extended templates) carrying html taint."""
    parsed = project.blade.get(template)
    if parsed is None:
        return []

    visited_set = visited if visited is not None else set()
    if template in visited_set:
        return []
    visited_set = visited_set | {template}

    local_bound = dict(bound)
    local_state = LocalState(local_bound, None)
    for foreach_stmt in find_all(parsed.tree.root_node, "foreach_statement"):
        collection_node, loop_vars = _extract_foreach_vars(foreach_stmt, parsed.source)
        if collection_node is not None:
            kinds = expr_kinds(collection_node, parsed.source, local_state)
            if kinds:
                for var_name in loop_vars:
                    local_bound[var_name] = kinds

    paths: list[list[PathStep]] = []

    # 1. Direct raw echos in this template
    is_blade = str(parsed.path).endswith(".blade.php")
    for stmt in find_all(parsed.tree.root_node, "echo_statement"):
        if TaintKind.HTML not in expr_kinds(stmt, parsed.source, local_state):
            continue
        line = stmt.start_point[0] + 1

        rule_id = LARAVEL_BLADE_RAW_ECHO_RULE if is_blade else XSS_RULE
        paths.append(
            prefix
            + [
                PathStep(
                    role="sink",
                    span=node_span(stmt, parsed.path),
                    snippet=project.blade_line(parsed.path, line),
                    note="raw echo, no HTML escaping",
                    rule_id=rule_id,
                )
            ]
        )

    # 1b. JS context sinks in this template
    for call in find_all(parsed.tree.root_node, "function_call_expression"):
        func_node = call.child_by_field_name("function")
        if func_node and node_text(func_node, parsed.source) == "vigilloo_js_sink":
            args = call.child_by_field_name("arguments")
            if args and TaintKind.JS in expr_kinds(args, parsed.source, local_state):
                line = call.start_point[0] + 1
                paths.append(
                    prefix
                    + [
                        PathStep(
                            role="sink",
                            span=node_span(call, parsed.path),
                            snippet=project.blade_line(parsed.path, line),
                            note="echo inside JS context without JS escaping",
                            rule_id=LARAVEL_BLADE_RAW_ECHO_RULE if is_blade else XSS_RULE,
                        )
                    ]
                )

    # 2. Includes, extends, components inside this template
    for stmt in find_all(parsed.tree.root_node, "expression_statement"):
        for binding in extract_view_bindings(stmt, parsed.source):
            if binding.template is None:
                continue
            sub_template = template_path(binding.template)
            if sub_template is None or sub_template not in project.blade:
                continue

            child_bound = dict(local_bound)
            for name, expression in binding.variables:
                kinds = expr_kinds(expression, parsed.source, local_state)
                if kinds:
                    child_bound[name] = kinds
            for name in binding.compacted:
                kinds = local_bound.get(name, frozenset())
                if kinds:
                    child_bound[name] = kinds

            step = PathStep(
                role="propagator",
                span=node_span(stmt, parsed.path),
                snippet=project.blade_line(parsed.path, stmt.start_point[0] + 1),
                note=f"view data into {sub_template}",
            )
            paths.extend(
                _walk_template(
                    project,
                    sub_template,
                    child_bound,
                    prefix + [step],
                    stats=stats,
                    visited=visited_set,
                )
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
    receiver_fqn: str | None = None,
    visited: frozenset[tuple[str, frozenset[tuple[str, frozenset[TaintKind]]]]] | None = None,
    route: Route | None = None,
) -> list[list[PathStep]]:
    if depth > max_depth:
        return []

    if visited is None:
        visited = frozenset()

    cache_key = frozenset(tainted.items())
    call_key = (fqn, cache_key)

    if call_key in visited:
        summary = project.summaries.get(fqn)
        if summary:
            return [prefix + p for p in summary.paths_by_taint.get(cache_key, [])]
        return []

    new_visited = visited | {call_key}

    if fqn not in project.summaries:
        from .summaries import FunctionSummary

        project.summaries[fqn] = FunctionSummary(fqn=fqn)
    summary = project.summaries[fqn]

    if cache_key not in summary.paths_by_taint:
        summary.paths_by_taint[cache_key] = []

        while True:
            inner_paths = _walk_method_ast(
                project, fqn, tainted, depth, max_depth, stats, receiver_fqn, new_visited, route
            )
            if len(inner_paths) == len(summary.paths_by_taint[cache_key]):
                break
            summary.paths_by_taint[cache_key] = inner_paths

    return [prefix + p for p in summary.paths_by_taint[cache_key]]


def _anti_sanitizer_steps(
    node: Node,
    source: bytes,
    parsed: ParsedFile,
    local: LocalState,
    request_vars: frozenset[str],
    resolve: ClassResolver | None,
    validated_fields: dict[str, frozenset[TaintKind]] | None,
) -> list[PathStep]:
    """Steps for anti-sanitizers called on tainted data within this expression."""
    steps: list[PathStep] = []
    for call in find_all(node, "function_call_expression"):
        invoked = call.child_by_field_name("function")
        if invoked is None or invoked.type not in ("name", "qualified_name"):
            continue
        fname = node_text(invoked, source)
        if not is_anti_sanitizer(fname):
            continue
        args_node = call.child_by_field_name("arguments")
        if args_node is None:
            continue
        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
        # Only emit if the argument is tainted. Anti-sanitizers usually take one primary argument.
        if any(
            expr_kinds(arg, source, local, request_vars, resolve, validated_fields) for arg in args
        ):
            steps.append(
                PathStep(
                    role="sanitizer",
                    span=node_span(call, parsed.path),
                    snippet=node_text(call, source).strip(),
                    note="weak control",
                )
            )
    return steps


def _is_html_response(node: Node, source: bytes) -> bool:
    """True if this AST node represents an HTTP response that is rendered as HTML.

    This includes:
    - response($tainted)
    - response($tainted)->header('Content-Type', 'text/html')
    It excludes:
    - response()->json(...)
    - response($tainted)->header('Content-Type', 'application/json')
    """
    if node.type == "function_call_expression":
        fname_node = node.child_by_field_name("function")
        if fname_node and node_text(fname_node, source) == "response":
            args = node.child_by_field_name("arguments")
            if args and [a for a in args.children if a.type not in ("(", ")", ",")]:
                return True  # response($content) defaults to HTML

    if node.type in _MEMBER_CALLS:
        method_node = node.child_by_field_name("name")
        if method_node:
            method_name = node_text(method_node, source)
            obj = node.child_by_field_name("object")

            if method_name == "json":
                return False

            if obj and not _is_html_response(obj, source):
                return False

            if method_name == "header":
                args_node = node.child_by_field_name("arguments")
                if args_node:
                    header_args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
                    if len(header_args) >= 2:
                        header_name = node_text(header_args[0], source).strip("'\"").lower()
                        header_val = node_text(header_args[1], source).strip("'\"").lower()
                        if header_name == "content-type" and "json" in header_val:
                            return False
            return True

    return False


def _walk_method_ast(
    project: Project,
    fqn: str,
    tainted: dict[str, frozenset[TaintKind]],
    depth: int,
    max_depth: int,
    stats: WalkStats | None = None,
    receiver_fqn: str | None = None,
    visited: frozenset[tuple[str, frozenset[tuple[str, frozenset[TaintKind]]]]] | None = None,
    route: Route | None = None,
) -> list[list[PathStep]]:
    """Walk one method body, returning every completed source-to-sink path.

    `fqn` is the method requested at the call site and `receiver_fqn` is the class
    the call was made on, which `$this` and `static::` mean. For an inherited or
    trait-provided method those differ from the class that owns the body, and all
    three are needed at once: the body comes from the declaring type, `$this`
    dispatches on the receiver, and `self::` stays bound where the code was written.
    Collapsing them would either lose a consumer's override or bind a trait's
    `self::` to the wrong type.
    """
    found = project.method_node(fqn)
    if found is None:
        return []
    method_node, parsed = found
    source = parsed.source
    requested_class = fqn.rpartition("::")[0]
    # What `$this` and `static::` mean: the class the call was made on.
    runtime_class = receiver_fqn or requested_class
    symbol = project.method(fqn)
    # What `self::` means: the class or trait whose file this body is in.
    lexical_class = symbol.fqn.rpartition("::")[0] if symbol is not None else requested_class
    paths: list[list[PathStep]] = []
    request_vars = _request_like_params(project, fqn, route if depth == 0 else None)

    # Bound to this file, because a class name means whatever this file's namespace and
    # imports say it means. `use App\\Support\\Input;` and Laravel's `Input` facade are
    # the same five letters and must not be the same source.
    def resolve(written: str) -> str | None:
        return project.resolve_class_name(parsed.path, written)

    # Variable name -> class FQN, for `$order->update($request->all())`. Seeded
    # from the signature, because a type-hinted parameter is route-model
    # binding, and `$order->update(...)` in an action whose signature binds the
    # model is where this bug actually ships.
    local_types: dict[str, str] = {}
    if symbol is not None:
        for param_name, param_type in zip(symbol.params, symbol.param_types, strict=True):
            if param_type:
                local_types[param_name] = param_type

    initial_tainted = dict(tainted)

    # cfg = CFGBuilder().build(method_node.child_by_field_name("body") or method_node)
    # ssa = SSABuilder(cfg, source)
    # ssa.build()

    ssa_taints: dict[SSAValue, frozenset[TaintKind]] = {}

    def resolve_ssa_taint(
        val: SSAValue, visited: set[SSAValue] | None = None
    ) -> frozenset[TaintKind]:
        if visited is None:
            visited = set()
        if val in visited:
            return frozenset()
        visited.add(val)

        if isinstance(val, PhiNode):
            res: frozenset[TaintKind] = frozenset()
            for src in val.sources:
                res = res.union(resolve_ssa_taint(src, visited))
            return res
        if val in ssa_taints:
            return ssa_taints[val]
        return initial_tainted.get(val.name, frozenset())

    def get_taint(name: str, node: Node) -> frozenset[TaintKind]:
        if node.id in ssa.reads:
            return resolve_ssa_taint(ssa.reads[node.id])
        return initial_tainted.get(name, frozenset())

    from .laravel.validation import extract_validation_cleared

    validated_fields = extract_validation_cleared(method_node, source, parsed)

    explored_states: set[tuple[int, frozenset[tuple[str, frozenset[TaintKind]]]]] = set()

    def explore(
        block: BasicBlock,
        current_prefix: list[PathStep],
        visited_edges: frozenset[tuple[int, int]],
        current_linear: dict[str, frozenset[TaintKind]],
        current_local_types: dict[str, str],
    ) -> None:
        state_key = (block.id, frozenset(current_linear.items()))
        if state_key in explored_states:
            return
        explored_states.add(state_key)

        prefix = current_prefix.copy()
        local_types = current_local_types.copy()
        linear_state = current_linear.copy()
        local = LocalState(linear_state, get_taint, project, local_types)

        for stmt in block.statements:
            anti_steps = _anti_sanitizer_steps(
                stmt, source, parsed, local, request_vars, resolve, validated_fields
            )
            if anti_steps:
                prefix = prefix + anti_steps

            # 1. Assignment from a Request source, or from an already tainted value.
            for assign in find_all(stmt, "assignment_expression"):
                left = assign.child_by_field_name("left")
                right = assign.child_by_field_name("right")
                if left is None or right is None:
                    continue
                target = _var_name(left, source)

                # `$u = User::find($id)` and `$u = new User(...)` both make $u a
                # User, which is what lets the instance-form Eloquent writes below
                # resolve their receiver.
                constructed = _constructed_class(right, source, project, parsed.path)
                if constructed is not None:
                    local_types[target] = constructed
                else:
                    local_types.pop(target, None)

                kinds = expr_kinds(right, source, local, request_vars, resolve, validated_fields)

                # Find the written SSAValue to update its taint
                val = None
                if left.id in ssa.writes:
                    val = ssa.writes[left.id]
                elif left.type == "subscript_expression":
                    base = left.child_by_field_name("array") or (
                        left.children[0] if left.children else None
                    )
                    if base and base.id in ssa.writes:
                        val = ssa.writes[base.id]

                if kinds:
                    if val:
                        ssa_taints[val] = kinds
                    local.linear_state[target] = kinds
                else:
                    # Reassigned from a clean or fully sanitized value: whatever
                    # taint the target carried before this statement no longer
                    # applies.
                    if val:
                        # Pop isn't strictly necessary since it wouldn't be in ssa_taints yet
                        ssa_taints.pop(val, None)
                    local.linear_state.pop(target, None)

                # expr_kinds computes *what* the value carries; the evidence path
                # still has to record *where* it entered, so the crossing is
                # detected separately. The step is emitted even when a sanitizer
                # cleared every kind, because it costs nothing on a path that then
                # never reaches a sink, and omitting it would drop the source step
                # from a path where only one kind was cleared.
                entered = _source_note(right, source, request_vars, resolve, local)
                if entered is not None:
                    prefix = prefix + [
                        PathStep(
                            role="source",
                            span=node_span(assign, parsed.path),
                            snippet=node_text(assign, source).strip(),
                            note=entered,
                        )
                    ]

            for shell_expr in find_all(stmt, "shell_command_expression"):
                if TaintKind.SHELL in expr_kinds(
                    shell_expr, source, local, request_vars, resolve, validated_fields
                ):
                    sink_step = PathStep(
                        role="sink",
                        span=node_span(shell_expr, parsed.path),
                        snippet=node_text(shell_expr, source).strip(),
                        note="shell execution operator (backticks)",
                        rule_id=COMMAND_INJECTION_RULE,
                    )
                    paths.append(prefix + [sink_step])

            # Dynamic include/require - language constructs (`include $x`,
            # `require_once $x`) that execute a file whose path comes off the wire.
            # Tree-sitter parses them as include_expression / require_expression, not
            # as function_call_expression, so the 2c loop above does not reach them.
            # Treated as code execution (CWE-98 LFI/RFI) because an attacker who
            # controls the path can load arbitrary code.
            for _node_type in (
                "include_expression",
                "include_once_expression",
                "require_expression",
                "require_once_expression",
            ):
                for inc_expr in find_all(stmt, _node_type):
                    # The operand is the first non-keyword child.
                    operand = next(
                        (
                            c
                            for c in inc_expr.children
                            if c.type not in ("include", "include_once", "require", "require_once")
                        ),
                        None,
                    )
                    if operand is None:
                        continue
                    if TaintKind.CODE not in expr_kinds(
                        operand, source, local, request_vars, resolve, validated_fields
                    ):
                        continue
                    paths.append(
                        prefix
                        + [
                            PathStep(
                                role="sink",
                                span=node_span(inc_expr, parsed.path),
                                snippet=node_text(inc_expr, source).strip(),
                                note="dynamic file inclusion (LFI/RFI)",
                                rule_id=CODE_EXECUTION_RULE,
                            )
                        ]
                    )

            # preg_replace with /e modifier - argument 0 is the pattern and argument
            # 1 is the replacement that gets eval'd. Tainted pattern fires CWE-94.
            # Removed in PHP 7 but still found in legacy codebases.
            for call in find_all(stmt, "function_call_expression"):
                invoked = call.child_by_field_name("function")
                if invoked is None or invoked.type not in ("name", "qualified_name"):
                    continue
                if node_text(invoked, source) != "preg_replace":
                    continue
                args_node = call.child_by_field_name("arguments")
                if args_node is None:
                    continue
                args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
                if not args:
                    continue
                # The pattern is arg 0 - check if a string literal contains /e.
                pattern_arg = args[0]
                pattern_text = node_text(pattern_arg, source).lower()
                if "/e" not in pattern_text and "\\x65" not in pattern_text:
                    continue
                # Pattern contains /e - check if a tainted value reaches any argument.
                if any(
                    TaintKind.CODE
                    in expr_kinds(a, source, local, request_vars, resolve, validated_fields)
                    for a in args
                ):
                    paths.append(
                        prefix
                        + [
                            PathStep(
                                role="sink",
                                span=node_span(call, parsed.path),
                                snippet=node_text(call, source).strip(),
                                note="preg_replace with /e evaluates replacement as PHP code",
                                rule_id=CODE_EXECUTION_RULE,
                            )
                        ]
                    )

            # 2a. Static calls. `User::create($request->all())` names its class at
            #     the call site, so it needs no receiver inference - which is why
            #     it is the form the mass-assignment rule leans on. The same
            #     property is what makes `DB::raw($sql)` reachable: the receiver is
            #     written down, so a sink can require one without inferring it.
            for call in find_all(stmt, "scoped_call_expression"):
                parts = _scoped_parts(call, source)
                if parts is None:
                    continue
                written, name, args = parts
                scoped_receiver_fqn = _scoped_receiver(
                    project, written, lexical_class, runtime_class, parsed.path
                )

                steps = _mass_assign_steps(
                    project,
                    call,
                    name,
                    args,
                    scoped_receiver_fqn,
                    parsed,
                    local,
                    request_vars,
                    resolve,
                )
                if steps is not None:
                    # Empty means "resolved and safe" - stop here rather than let the
                    # propagator handling below record a lost trail, exactly as 2b does.
                    if steps:
                        paths.append(prefix + steps)
                    continue

                # A receiver-scoped sink first, then the name-keyed table. Order matters only
                # for readability today, since no name appears in both, but the scoped table is
                # the more specific statement and a more specific rule losing to a general one
                # is the kind of thing that is invisible until the general one is widened.
                found_sinks = static_sinks(scoped_receiver_fqn, name) + sinks(name)
                for scoped_sink in found_sinks:
                    sink_steps = _sink_steps(
                        call,
                        args,
                        scoped_sink,
                        parsed,
                        name,
                        local,
                        request_vars,
                        resolve,
                        validated_fields,
                    )

                    if sink_steps:
                        paths.append(prefix + sink_steps)
                if found_sinks:
                    continue

                paths.extend(
                    _follow_static(
                        project,
                        call,
                        scoped_receiver_fqn,
                        name,
                        args,
                        parsed,
                        local,
                        request_vars,
                        prefix,
                        depth,
                        max_depth,
                        stats,
                        resolve,
                        visited=visited,
                    )
                )

            # 2b. Calls: either a sink, or a step deeper into another method. Both
            #     spellings of the operator, because `$repo?->search($tainted)` is
            #     the same call as `$repo->search($tainted)` and stopping at one of
            #     them loses the trail without recording that anything was lost.
            for call in find_any(stmt, _MEMBER_CALLS):
                obj, name, args = _call_parts(call, source)

                steps = _mass_assign_steps(
                    project,
                    call,
                    name,
                    args,
                    local_types.get(obj.lstrip("$")),
                    parsed,
                    local,
                    request_vars,
                    resolve,
                )
                if steps is not None:
                    # Empty means "resolved and safe" - stop here without letting
                    # the propagator handling below record a lost trail.
                    if steps:
                        paths.append(prefix + steps)
                    continue

                receiver_type = local_types.get(obj.lstrip("$"))
                found_sinks = static_sinks(receiver_type, name) + sinks(name)
                for sink_found in found_sinks:
                    sink_steps = _sink_steps(
                        call,
                        args,
                        sink_found,
                        parsed,
                        name,
                        local,
                        request_vars,
                        resolve,
                        validated_fields,
                    )

                    if sink_steps:
                        paths.append(prefix + sink_steps)
                if found_sinks:
                    continue

                # Which arguments carry tainted data, and which kinds. Computed
                # before the give-up checks because a give-up only counts as a lost
                # trail when there was something to lose: counting every unresolved
                # receiver fires on benign calls like $request->input() and a
                # ->get() chain terminator, and a counter that reports gaps on
                # correct code trains people to ignore it.
                passed = {
                    i: kinds
                    for i, arg in enumerate(args)
                    if (kinds := expr_kinds(arg, source, local, request_vars, resolve))
                }

                # `$this->method($tainted)` resolves through the enclosing class,
                # including its traits and parents. `$this->prop->method(...)`
                # resolves through the property's declared type.
                target_class: str | None
                if obj == "$this":
                    target_class = runtime_class
                elif obj.startswith("$this->"):
                    prop = obj.removeprefix("$this->")
                    target_class = project.resolve_property_type(runtime_class, prop)
                else:
                    target_class = None

                candidates = []
                confidence = 1.0

                if target_class is None:
                    for cls_fqn in project.classes:
                        if project.method(f"{cls_fqn}::{name}") is not None:
                            candidates.append(cls_fqn)
                    if not candidates:
                        if passed:
                            _giveup(stats)
                        continue
                    confidence = 0.4 if len(candidates) == 1 else 0.4 / len(candidates)
                else:
                    candidates = project.bindings.get(target_class, [target_class])
                    if target_class in project.bindings:
                        confidence = 0.9 if len(candidates) == 1 else 0.6 / len(candidates)
                    else:
                        confidence = 1.0 if obj == "$this" else 0.95

                found_callee = False

                for candidate in candidates:
                    callee_fqn = f"{candidate}::{name}"
                    callee = project.method(callee_fqn)
                    if callee is None:
                        continue

                    found_callee = True
                    if not passed:
                        continue

                    _followed(stats)
                    callee_tainted = {
                        callee.params[i]: kinds
                        for i, kinds in passed.items()
                        if i < len(callee.params)
                    }
                    if not callee_tainted:
                        continue

                    step = PathStep(
                        role="propagator",
                        span=node_span(call, parsed.path),
                        snippet=node_text(call, source).strip(),
                        note=f"argument {min(passed)} into {callee.fqn}",
                        confidence=confidence,
                    )

                    inner_paths = _walk_method(
                        project,
                        callee_fqn,
                        callee_tainted,
                        [],
                        depth + 1,
                        max_depth,
                        stats,
                        candidate,
                        visited=visited,
                    )

                    for inner_path in inner_paths:
                        paths.append(prefix + [step] + inner_path)

                if not found_callee and passed:
                    _giveup(stats)

            # 2c. Named function call sinks: `exec($cmd)`, `shell_exec($cmd)`, etc.
            #     Checked before the dynamic-callee give-up below. The distinction
            #     is between a *named* callee whose text appears in the SINKS table
            #     (a security hazard) and an *unresolvable* callee whose identity
            #     is not known (a coverage gap). The first is a finding; the second
            #     is a give-up.
            for call in find_all(stmt, "function_call_expression"):
                invoked = call.child_by_field_name("function")
                if invoked is None:
                    continue
                if invoked.type not in ("name", "qualified_name"):
                    continue
                fname = node_text(invoked, source)
                args_node = call.child_by_field_name("arguments")
                args = (
                    [a for a in args_node.children if a.type not in ("(", ")", ",")]
                    if args_node is not None
                    else []
                )

                # Special case for curl_setopt
                if fname == "curl_setopt":
                    if len(args) >= 3 and node_text(args[1], source).strip() == "CURLOPT_URL":
                        sink_steps = _sink_steps(
                            call,
                            args,
                            (2, TaintKind.URL, "php.ssrf"),
                            parsed,
                            fname,
                            local,
                            request_vars,
                            resolve,
                            validated_fields,
                        )
                        if sink_steps:
                            paths.append(prefix + sink_steps)
                    continue

                found_sinks = sinks(fname)
                if not found_sinks:
                    continue
                for sink_found in found_sinks:
                    sink_steps = _sink_steps(
                        call,
                        args,
                        sink_found,
                        parsed,
                        fname,
                        local,
                        request_vars,
                        resolve,
                        validated_fields,
                    )
                    if sink_steps:
                        paths.append(prefix + sink_steps)

            # 2d. Dynamic invocation: `$fn($tainted)`, `($handler->method)($tainted)`.
            #     docs/03-parser is explicit about these - "Dynamic dispatch. Mark the
            #     edge unresolved" - and until now they were not marked at all. There is
            #     no loop over function_call_expression in this walk, so a tainted value
            #     handed to a variable callee vanished: no finding, and no give-up either,
            #     so the resolution rate reported full coverage over a trail it had lost.
            #     That is precisely the combination invariant 4 exists to prevent.
            #
            #     Only a *dynamic* callee counts. A written name - `strlen($x)`,
            #     `sprintf($x)`, `\strlen($x)` - is skipped, and that exclusion is what
            #     keeps the number meaningful: every PHP file is full of calls to builtins
            #     and to project functions, none of which this walk was ever going to
            #     enter, and counting them would bury the one call that genuinely lost a
            #     trail under thousands that never had one. `name` and `qualified_name`
            #     are both literal spellings of a known callee; anything else - a
            #     variable, a parenthesised expression, an array offset - is a callee
            #     whose identity is not knowable here.
            #
            #     ponytail: the edge is counted, not followed. Following it needs the set
            #     of closures a variable may hold, which is a data-flow question this
            #     statement-order walk cannot answer - see docs/05-data-flow-analysis.
            #     The upgrade trigger is a fixture where a closure assigned in one branch
            #     reaches a sink, at which point the give-up here becomes a real edge.
            for call in find_all(stmt, "function_call_expression"):
                invoked = call.child_by_field_name("function")
                if invoked is None or invoked.type in ("name", "qualified_name"):
                    continue
                args_node = call.child_by_field_name("arguments")
                if args_node is None:
                    continue
                dynamic_args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
                # Same condition as every other give-up in this walk: a call is only a
                # lost trail when something was being carried into it. `$fn()` and
                # `$fn($constant)` lose nothing, and `$fn(...)` is a first-class callable
                # that has not been invoked yet - nothing is passed to any of them.
                if any(
                    expr_kinds(arg, source, local, request_vars, resolve) for arg in dynamic_args
                ):
                    _giveup(stats)

            # 3. view() hands data to a template, where html taint can reach a
            #    raw echo. A statement can hold more than one view() call, as in a

            #    ternary choosing between two templates, so each is walked.
            for binding in extract_view_bindings(stmt, source):
                bound: dict[str, frozenset[TaintKind]] = {}
                for name, expression in binding.variables:
                    kinds = expr_kinds(expression, source, local, request_vars, resolve)
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

                _followed(stats)
                step = PathStep(
                    role="propagator",
                    span=node_span(stmt, parsed.path),
                    snippet=node_text(stmt, source).strip(),
                    note=f"view data into {template}",
                )
                paths.extend(_walk_template(project, template, bound, prefix + [step], stats))

            # 4. HTTP response sinks (e.g. response($tainted)->header('Content-Type', 'text/html'))
            for return_stmt in find_all(stmt, "return_statement"):
                ret_exprs = [c for c in return_stmt.children if c.type not in ("return", ";")]
                if ret_exprs:
                    ret_expr = ret_exprs[0]
                    if _is_html_response(ret_expr, source):
                        if TaintKind.HTML in expr_kinds(
                            ret_expr, source, local, request_vars, resolve, validated_fields
                        ):
                            paths.append(
                                prefix
                                + [
                                    PathStep(
                                        role="sink",
                                        span=node_span(return_stmt, parsed.path),
                                        snippet=node_text(return_stmt, source).strip(),
                                        note="returned as an HTML response",
                                        rule_id=XSS_RULE,
                                    )
                                ]
                            )

        for edge in block.successors:
            edge_tuple = (block.id, edge.target.id)
            if edge_tuple not in visited_edges:
                explore(
                    edge.target,
                    prefix,
                    visited_edges.union({edge_tuple}),
                    linear_state,
                    local_types,
                )

    cfg = CFGBuilder().build(method_node.child_by_field_name("body") or method_node)
    ssa = SSABuilder(cfg, source)
    ssa.build()

    if cfg.entry:
        explore(cfg.entry, [], frozenset(), dict(tainted), local_types)

    return paths


def _route_param_sources(
    project: Project, route: Route
) -> tuple[dict[str, frozenset[TaintKind]], list[PathStep]]:
    """The action parameters this route binds from its URI, and the step that says so.

    docs/06-taint-analysis: "Route parameters injected into controller signatures are
    sources: public function show(Request $r, string $slug) - $slug is
    attacker-controlled." Nothing in the body marks the crossing - the value is already
    in the variable when the first line runs - so unlike every other source this one is
    seeded at the entry point rather than recognised in an expression.

    Matching is by name, because that is how Laravel binds: `{slug}` fills the parameter
    called `$slug` wherever it sits in the signature, which is why the Request parameter
    beside it does not shift the position. A parameter the URI does not name is not
    bound at all and is left clean.

    The step exists so the path still says where the data entered. An entry step alone
    would leave a developer reading "GET /pages/{slug}" and then a sink, with nothing
    naming the variable that carried the payload between them, and invariant 2 is about
    the path being followable rather than merely present.
    """
    symbol = project.method(route.action_fqn)
    if symbol is None:
        return {}, []

    declared = set(uri_params(route.uri))
    bound = [
        (name, param_type)
        for name, param_type in zip(symbol.params, symbol.param_types, strict=True)
        if name in declared and route_param_is_source(param_type)
    ]
    if not bound:
        return {}, []

    seeded = {name: ROUTE_PARAM_KINDS for name, _ in bound}
    written = ", ".join(f"{ptype} ${name}" if ptype else f"${name}" for name, ptype in bound)
    return seeded, [
        PathStep(
            role="source",
            span=symbol.span,
            snippet=written,
            note="attacker-controlled route parameter, bound from the URL",
        )
    ]


def find_taint_paths(
    project: Project, max_depth: int = 5, stats: WalkStats | None = None
) -> list[list[PathStep]]:
    """Every source-to-sink path reachable from a route entry point."""
    paths: list[list[PathStep]] = []

    for route in project.routes:
        if not route.action_fqn:
            _giveup(stats)
            continue
        _followed(stats)

        auth_middleware = authenticated_by(route)
        note = "HTTP entry point"
        if auth_middleware is None:
            note = "HTTP entry point (unauthenticated)"

        entry = PathStep(
            role="entry",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri} -> {route.action_fqn}",
            note=note,
        )
        seeded, source_steps = _route_param_sources(project, route)
        paths.extend(
            _walk_method(
                project,
                route.action_fqn,
                seeded,
                [entry, *source_steps],
                0,
                max_depth,
                stats,
                route=route,
            )
        )

    for ep in project.entrypoints:
        _followed(stats)
        entry = PathStep(
            role="entry",
            span=ep.span,
            snippet=f"[{ep.kind}] {ep.fqn}",
            note=f"{ep.kind.capitalize()} entry point",
        )
        # Entry points start with $this properties assumed to be attacker-controlled.
        # This is because jobs/commands receive arbitrary payloads via their constructor
        # which are typically saved to properties.
        from .models import ALL_KINDS

        seeded = {"this": ALL_KINDS}

        paths.extend(_walk_method(project, ep.fqn, seeded, [entry], 0, max_depth, stats))

    # Walking nested statements can reach the same call twice, so collapse
    # paths that are step-for-step identical before returning.
    unique: dict[tuple[tuple[str, str, int, str | None], ...], list[PathStep]] = {}
    for path in paths:
        key = tuple((s.role, str(s.span.file), s.span.start_line, s.rule_id) for s in path)
        unique.setdefault(key, path)

    return sorted(unique.values(), key=lambda p: (str(p[-1].span.file), p[-1].span.start_line))
