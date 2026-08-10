"""Extract the Laravel route table, the application's attack surface inventory."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from ..models import Route, WalkStats
from ..parser import ParsedFile, find_all, node_span, node_text
from ..symbols import FileSymbols, array_literal

# {order} and Laravel's optional {order?}.
_URI_PARAM = re.compile(r"\{(\w+)\??\}")

UNRESOLVED_MIDDLEWARE = "?"

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
    return _URI_PARAM.findall(uri)


def _string_literal(node: Node, source: bytes) -> str:
    return node_text(node, source).strip("'\"")


def _is_dynamic(uri_node: Node, call_node: Node) -> bool:
    inner = uri_node.children[0] if uri_node.type == "argument" and uri_node.children else uri_node
    if inner.type not in ("string", "encapsed_string"):
        return True
    
    curr: Node | None = call_node.parent
    while curr:
        if curr.type in ("foreach_statement", "for_statement", "while_statement", "do_statement"):
            return True
        curr = curr.parent
    return False


def _action_fqn(node: Node, source: bytes, symbols: FileSymbols) -> str:
    text = node_text(node, source)

    if "::class" in text:
        short = text.split("::class")[0].strip().lstrip("[").strip()
        if "," in text:
            method = text.rsplit(",", 1)[-1].strip().rstrip("]").strip("'\" ")
        else:
            method = "__invoke"  # Single action controller
        cls = symbols.imports.get(short, short)
        return f"{cls}::{method}"

    literal = text.strip("'\"")
    if "@" in literal:
        short, method = literal.split("@", 1)
        return f"{symbols.imports.get(short, short)}::{method}"
    elif literal.isalnum():
        return f"{symbols.imports.get(literal, literal)}::__invoke"

    return ""


def _parse_array_dict(node: Node, source: bytes) -> dict[str, list[str]]:
    """Parse ['prefix' => 'admin', 'middleware' => ['auth', 'can:manage']] into a dict."""
    result: dict[str, list[str]] = {}
    for element in node.children:
        if element.type != "array_element_initializer":
            continue

        if len(element.children) >= 3 and element.children[1].type == "=>":
            key_node = element.children[0]
            val_node = element.children[2]
            key = node_text(key_node, source).strip("'\"")

            if val_node.type in ("string", "encapsed_string"):
                result[key] = [node_text(val_node, source).strip("'\"")]
            elif val_node.type == "array_creation_expression":
                vals: list[str] = []
                for val_elem in val_node.children:
                    if val_elem.type == "array_element_initializer":
                        if len(val_elem.children) == 1 and val_elem.children[0].type in (
                            "string",
                            "encapsed_string",
                        ):
                            vals.append(node_text(val_elem.children[0], source).strip("'\""))
                result[key] = vals
    return result


def _unroll_chain(node: Node, source: bytes) -> list[tuple[str, Node]]:
    """Unroll A()->B()->C() into a list of calls."""
    calls: list[tuple[str, Node]] = []
    curr: Node | None = node
    while curr is not None:
        if curr.type == "member_call_expression":
            name = node_text(curr.child_by_field_name("name"), source)
            calls.append((name, curr))
            curr = curr.child_by_field_name("object")
        elif curr.type == "scoped_call_expression":
            name = node_text(curr.child_by_field_name("name"), source)
            scope = node_text(curr.child_by_field_name("scope"), source)
            calls.append((f"{scope}::{name}", curr))
            break
        else:
            break

    if not calls or not calls[-1][0].startswith("Route::"):
        return []

    return list(reversed(calls))


@dataclass
class GroupContext:
    prefix: str = ""
    name: str = ""
    middleware: list[str] = field(default_factory=list)


class RouteWalker:
    def __init__(
        self,
        parsed: ParsedFile,
        symbols: FileSymbols,
        stats: WalkStats | None,
        middleware_groups: dict[str, list[str]],
    ):
        self.parsed = parsed
        self.source = parsed.source
        self.symbols = symbols
        self.stats = stats
        self.routes: list[Route] = []
        self.group_stack: list[GroupContext] = [GroupContext()]
        self.middleware_groups = middleware_groups

    @property
    def current_context(self) -> GroupContext:
        ctx = GroupContext()
        for g in self.group_stack:
            if g.prefix:
                ctx.prefix = f"{ctx.prefix}/{g.prefix}".strip("/")
            if g.name:
                ctx.name = f"{ctx.name}{g.name}"
            ctx.middleware.extend(g.middleware)
        return ctx

    def get_closure(self, call: Node) -> Node | None:
        args_node = call.child_by_field_name("arguments")
        if not args_node:
            return None
        for arg in args_node.children:
            if arg.type == "argument":
                inner = arg.children[0] if arg.children else None
                if inner and inner.type == "anonymous_function":
                    return inner
        return None

    def _parse_chain_properties(self, chain: list[tuple[str, Node]]) -> GroupContext:
        ctx = GroupContext()
        for name, call in chain:
            if name.split("::")[-1] == "prefix":
                args_node = call.child_by_field_name("arguments")
                if args_node and len(args_node.children) >= 2:
                    arg = args_node.children[1]  # [0] is '(', [1] is argument
                    inner = arg.children[0] if arg.children else None
                    if inner and inner.type in ("string", "encapsed_string"):
                        ctx.prefix = _string_literal(inner, self.source)
            elif name.split("::")[-1] == "name":
                args_node = call.child_by_field_name("arguments")
                if args_node and len(args_node.children) >= 2:
                    arg = args_node.children[1]
                    inner = arg.children[0] if arg.children else None
                    if inner and inner.type in ("string", "encapsed_string"):
                        ctx.name = _string_literal(inner, self.source)
            elif name.split("::")[-1] == "middleware":
                args_node = call.child_by_field_name("arguments")
                if args_node and len(args_node.children) >= 2:
                    arg = args_node.children[1]
                    inner = arg.children[0] if arg.children else None
                    if inner and inner.type in ("string", "encapsed_string"):
                        ctx.middleware.append(_string_literal(inner, self.source))
                    elif inner and inner.type == "array_creation_expression":
                        vals = array_literal(inner, self.source)
                        if vals:
                            ctx.middleware.extend(vals)
                        else:
                            ctx.middleware.append(UNRESOLVED_MIDDLEWARE)
                    else:
                        ctx.middleware.append(UNRESOLVED_MIDDLEWARE)
        return ctx

    def _parse_group_array(self, call: Node) -> GroupContext:
        ctx = GroupContext()
        args_node = call.child_by_field_name("arguments")
        if not args_node or len(args_node.children) < 2:
            return ctx

        arg = args_node.children[1]
        inner = arg.children[0] if arg.children else None
        if inner and inner.type == "array_creation_expression":
            props = _parse_array_dict(inner, self.source)
            if "prefix" in props and props["prefix"]:
                ctx.prefix = props["prefix"][0]
            if "as" in props and props["as"]:
                ctx.name = props["as"][0]
            if "middleware" in props:
                ctx.middleware.extend(props["middleware"])
        return ctx

    def walk(self, node: Node) -> None:
        if node.type in ("member_call_expression", "scoped_call_expression"):
            chain = _unroll_chain(node, self.source)
            if chain:
                last_name, last_call = chain[-1]
                if last_name in ("group", "Route::group"):
                    ctx1 = self._parse_chain_properties(chain[:-1])
                    ctx2 = self._parse_group_array(last_call)

                    # Merge properties from both styles
                    merged = GroupContext(
                        prefix=ctx2.prefix if ctx2.prefix else ctx1.prefix,
                        name=ctx2.name if ctx2.name else ctx1.name,
                        middleware=ctx1.middleware + ctx2.middleware,
                    )

                    self.group_stack.append(merged)
                    closure = self.get_closure(last_call)
                    if closure:
                        self.walk(closure)
                    self.group_stack.pop()
                    return

                verb_method = chain[0][0].split("::")[1]
                if verb_method in _VERB_METHODS:
                    self.extract_route(chain, _VERB_METHODS[verb_method])
                    return
                elif verb_method in ("resource", "apiResource"):
                    self.extract_resource(chain, api_only=(verb_method == "apiResource"))
                    return

        for child in node.children:
            self.walk(child)

    def _expand_middleware(self, mw_list: list[str]) -> tuple[str, ...]:
        expanded = []
        for m in mw_list:
            if (
                hasattr(self, "middleware_groups")
                and self.middleware_groups
                and m in self.middleware_groups
            ):
                expanded.extend(self.middleware_groups[m])
            else:
                expanded.append(m)
        return tuple(expanded)

    def extract_route(self, chain: list[tuple[str, Node]], verbs: tuple[str, ...]) -> None:
        first_call = chain[0][1]
        args_node = first_call.child_by_field_name("arguments")
        if not args_node:
            if self.stats:
                self.stats.unresolved += 1
            return

        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
        if len(args) < 2:
            if self.stats:
                self.stats.unresolved += 1
            return

        if self.stats:
            self.stats.resolved += 1

        ctx1 = self._parse_chain_properties(chain[1:])
        curr = self.current_context

        is_dyn = _is_dynamic(args[0], first_call)
        if is_dyn:
            uri = "{dynamic}"
            confidence = 0.5
        else:
            uri = _string_literal(args[0], self.source)
            confidence = 1.0

        full_uri = f"{curr.prefix}/{uri}".strip("/") if curr.prefix else uri.strip("/")
        full_uri = re.sub(r"/+", "/", "/" + full_uri)

        action_fqn = _action_fqn(args[1], self.source, self.symbols)
        mw = self._expand_middleware(curr.middleware + ctx1.middleware)

        self.routes.append(
            Route(
                uri=full_uri,
                verbs=verbs,
                action_fqn=action_fqn,
                middleware=mw,
                span=node_span(first_call, self.parsed.path),
                confidence=confidence,
            )
        )

    def extract_resource(self, chain: list[tuple[str, Node]], api_only: bool) -> None:
        first_call = chain[0][1]
        args_node = first_call.child_by_field_name("arguments")
        if not args_node:
            if self.stats:
                self.stats.unresolved += 1
            return

        args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
        if len(args) < 2:
            if self.stats:
                self.stats.unresolved += 1
            return

        if self.stats:
            self.stats.resolved += 1

        ctx1 = self._parse_chain_properties(chain[1:])
        curr = self.current_context

        is_dyn = _is_dynamic(args[0], first_call)
        if is_dyn:
            base_uri = "{dynamic}"
            confidence = 0.5
        else:
            base_uri = _string_literal(args[0], self.source).strip("/")
            confidence = 1.0

        controller = _action_fqn(args[1], self.source, self.symbols)
        # If action_fqn parser thinks it is a method call due to string/class, it adds ::__invoke.
        # But resource passes controller class. _action_fqn returns `Controller::__invoke`.
        # Actually _action_fqn for `Controller::class` (no method) returns `Controller::__invoke`.
        # We need to strip ::__invoke to get the base controller name.
        if controller.endswith("::__invoke"):
            controller = controller[:-10]

        mw = self._expand_middleware(curr.middleware + ctx1.middleware)

        # Determine parameter name, e.g. 'posts' -> 'post' (Laravel uses singular).
        # We'll just use a generic 'id' or strip 's' for simplicity unless requested.
        # Laravel strips the last 's' for the param name.
        param_name = base_uri.split("/")[-1]
        if param_name.endswith("s"):
            param_name = param_name[:-1]

        actions = [
            ("index", ("GET", "HEAD"), f"/{base_uri}"),
            ("store", ("POST",), f"/{base_uri}"),
            ("show", ("GET", "HEAD"), f"/{base_uri}/{{{param_name}}}"),
            ("update", ("PUT", "PATCH"), f"/{base_uri}/{{{param_name}}}"),
            ("destroy", ("DELETE",), f"/{base_uri}/{{{param_name}}}"),
        ]
        if not api_only:
            actions.insert(1, ("create", ("GET", "HEAD"), f"/{base_uri}/create"))
            actions.insert(5, ("edit", ("GET", "HEAD"), f"/{base_uri}/{{{param_name}}}/edit"))

        for method, verbs, route_uri in actions:
            full_uri = f"{curr.prefix}{route_uri}" if curr.prefix else route_uri
            full_uri = re.sub(r"/+", "/", "/" + full_uri)

            self.routes.append(
                Route(
                    uri=full_uri,
                    verbs=verbs,
                    action_fqn=f"{controller}::{method}",
                    middleware=mw,
                    span=node_span(first_call, self.parsed.path),
                    confidence=confidence,
                )
            )


def extract_routes(
    parsed: ParsedFile,
    symbols: FileSymbols,
    stats: WalkStats | None = None,
    middleware_groups: dict[str, list[str]] | None = None,
) -> list[Route]:
    """Find Route::verb(uri, action) calls."""
    walker = RouteWalker(parsed, symbols, stats, middleware_groups or {})
    walker.walk(parsed.tree.root_node)
    return sorted(walker.routes, key=lambda r: (r.span.start_line, r.uri))


def discover_route_files(files: dict[Path, ParsedFile]) -> set[Path]:
    """Find files that define routes.

    Includes standard paths unconditionally, plus any file explicitly registered in a
    RouteServiceProvider via base_path(...).
    """
    paths = {
        Path("routes/web.php"),
        Path("routes/api.php"),
        Path("routes/console.php"),
        Path("routes/channels.php"),
    }

    for path, parsed in files.items():
        if path.name == "RouteServiceProvider.php" and "Providers" in path.parts:
            for call in find_all(parsed.tree.root_node, "function_call_expression"):
                name = call.child_by_field_name("function")
                if name and node_text(name, parsed.source) == "base_path":
                    args = call.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type == "argument":
                                inner = arg.children[0] if arg.children else None
                                if inner and inner.type in ("string", "encapsed_string"):
                                    paths.add(Path(_string_literal(inner, parsed.source)))

    return paths
