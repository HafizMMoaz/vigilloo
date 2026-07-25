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
