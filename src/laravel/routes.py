"""Extract the Laravel route table, the application's attack surface inventory."""

import re

from tree_sitter import Node

from ..models import Route, WalkStats
from ..parser import ParsedFile, find_all, node_span, node_text
from ..symbols import FileSymbols, array_literal

# {order} and Laravel's optional {order?}.
_URI_PARAM = re.compile(r"\{(\w+)\??\}")

# Middleware this module could not read as a string literal. Recorded rather
# than dropped: an authorization rule that silently discards `->middleware($m)`
# turns "I cannot tell what guards this route" into "nothing guards this
# route", which is a fabricated finding. Callers must treat it as unknown.
UNRESOLVED_MIDDLEWARE = "?"

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


def uri_params(uri: str) -> list[str]:
    """The parameter names a route URI declares, in the order they appear.

    `/invoices/{invoice}/lines/{line?}` yields ["invoice", "line"]. Public and
    shared: both the authorization rule and the taint walk need it, and Laravel
    binds a URI segment to an action parameter *by name*, so a second copy of
    this pattern that drifted would silently change which parameters are
    considered attacker-controlled.
    """
    return _URI_PARAM.findall(uri)


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


def _middleware_args(call: Node, source: bytes) -> list[str]:
    """The middleware names one ->middleware(...) call adds."""
    args_node = call.child_by_field_name("arguments")
    if args_node is None:
        return [UNRESOLVED_MIDDLEWARE]

    names: list[str] = []
    for arg in args_node.children:
        if arg.type != "argument":
            continue
        inner = arg.children[0] if arg.children else None
        if inner is None:
            names.append(UNRESOLVED_MIDDLEWARE)
        elif inner.type in ("string", "encapsed_string"):
            names.append(_string_literal(inner, source))
        elif inner.type == "array_creation_expression":
            values = array_literal(inner, source)
            names.extend(values if values is not None else [UNRESOLVED_MIDDLEWARE])
        else:
            names.append(UNRESOLVED_MIDDLEWARE)
    return names


def _middleware(call: Node, source: bytes) -> tuple[str, ...]:
    """Every middleware applied to a route registration.

    `Route::get(...)` is a scoped_call_expression and the `->middleware(...)`
    chained onto it is a member_call_expression whose *object* is that scoped
    call, so middleware is found by walking up from the registration rather than
    by reading its arguments. The group form -

        Route::middleware(['auth'])->group(function () { Route::get(...); });

    - is reached by the same walk continuing out through the closure to the
    enclosing ->group(...) call, then down its own receiver chain. Group
    middleware is how real route files are written; handling only the inline
    chain would report nothing on a typical routes/api.php.

    ponytail: middleware *groups* ('web', 'api') are not expanded into their
    member lists - that needs Kernel.php / bootstrap/app.php. An unexpanded
    group reads as "not authenticated", which costs findings and never
    fabricates one.
    """
    # Keyed by extent so a chain reached twice by the upward walk is collected
    # once, and so the result is ordered by position in the file. The *end*
    # byte is what distinguishes the links: every call in `a()->b()->c()`
    # starts where `a` does, so keying on the start alone silently collapses a
    # doubled ->middleware(...)->middleware(...) into one.
    found: dict[tuple[int, int], Node] = {}
    node: Node | None = call
    while node is not None:
        chain: Node | None = node
        while chain is not None and chain.type in (
            "member_call_expression",
            "scoped_call_expression",
        ):
            if node_text(chain.child_by_field_name("name"), source) == "middleware":
                found[(chain.start_byte, chain.end_byte)] = chain
            chain = chain.child_by_field_name("object")
        node = node.parent

    names: list[str] = []
    for _, mw_call in sorted(found.items()):
        names.extend(_middleware_args(mw_call, source))
    return tuple(names)


def extract_routes(
    parsed: ParsedFile, symbols: FileSymbols, stats: WalkStats | None = None
) -> list[Route]:
    """Find Route::verb(uri, action) calls.

    ponytail: no prefix/resource expansion yet. The fixture registers flat
    routes, and routes inside a middleware group are found because the search is
    over the whole file rather than statement by statement. Add expansion when a
    fixture needs it - see docs 08-framework-adapters.
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

        # Recognised as a verb-registering Route call, but the argument shape
        # did not match what a route registration looks like.
        args_node = call.child_by_field_name("arguments")
        if args_node is None:
            if stats is not None:
                stats.unresolved += 1
            continue
        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
        if len(args) < 2:
            if stats is not None:
                stats.unresolved += 1
            continue

        # The opposite branch of the two give-ups above: a Route::verb call
        # whose shape the adapter did understand. Without it the unresolved
        # count has no denominator and the rate in the report would have to be
        # estimated (docs/22-testing, section "Metrics gated in CI").
        if stats is not None:
            stats.resolved += 1

        routes.append(
            Route(
                uri=_string_literal(args[0], source),
                verbs=verbs,
                action_fqn=_action_fqn(args[1], source, symbols),
                middleware=_middleware(call, source),
                span=node_span(call, parsed.path),
            )
        )

    return sorted(routes, key=lambda r: (r.span.start_line, r.uri))
