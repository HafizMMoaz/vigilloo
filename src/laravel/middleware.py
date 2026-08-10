from tree_sitter import Node

from ..models import Route, TaintKind
from ..parser import ParsedFile


def _extract_string(node: Node, source: bytes) -> str | None:
    """Extracts a string from a string literal node, or returns None."""
    if node.type in ("string", "encapsed_string"):
        # Very basic string extraction, removing quotes
        return source[node.start_byte : node.end_byte].decode("utf-8").strip("'\"")
    elif node.type == "class_constant_access_expression":
        # Extract the fully qualified name
        if len(node.children) >= 3:
            name_node = node.children[-1]
            if (
                name_node.type == "name"
                and source[name_node.start_byte : name_node.end_byte].decode("utf-8") == "class"
            ):
                qname = node.children[0]
                if qname.type in ("qualified_name", "name", "identifier"):
                    qname_str = source[qname.start_byte : qname.end_byte].decode("utf-8")
                    if qname_str.startswith("\\"):
                        qname_str = qname_str[1:]
                    return qname_str
    return None


def extract_middleware_groups(parsed: ParsedFile) -> dict[str, list[str]]:
    """
    Extracts middleware groups mapping from Kernel.php (L9/10) or bootstrap/app.php (L11).
    Returns a dictionary mapping group names to lists of middleware names.
    """
    groups: dict[str, list[str]] = {}
    path_str = str(parsed.path)

    if "Kernel.php" in path_str:
        groups.update(_parse_kernel_groups(parsed.tree.root_node, parsed.source))
    elif "app.php" in path_str and "bootstrap" in path_str:
        groups.update(_parse_app_groups(parsed.tree.root_node, parsed.source))

    return groups


def _parse_kernel_groups(node: Node | None, source: bytes) -> dict[str, list[str]]:
    """
    Looks for:
    protected $middlewareGroups = [
        'web' => [ ... ],
        'api' => [ ... ],
    ];
    """
    groups: dict[str, list[str]] = {}
    prop_node = _find_property_declaration(node, "$middlewareGroups", source)
    if not prop_node:
        return groups

    # The default_value should be an array_creation_expression
    if prop_node.type == "array_creation_expression":
        for child in prop_node.children:
            if child.type == "array_element_initializer":
                # key => value
                if len(child.children) >= 3:
                    key_node = child.children[0]
                    val_node = child.children[2]
                    key = _extract_string(key_node, source)
                    if key and val_node.type == "array_creation_expression":
                        members = []
                        for val_child in val_node.children:
                            if val_child.type == "array_element_initializer":
                                # Extract single string or class
                                if len(val_child.children) >= 1:
                                    member = _extract_string(val_child.children[0], source)
                                    if member:
                                        members.append(member)
                        groups[key] = members
    return groups


def _find_property_declaration(node: Node | None, prop_name: str, source: bytes) -> Node | None:
    if node is None:
        return None
    if node.type == "property_declaration":
        for child in node.children:
            if child.type == "property_element":
                name_node = child.child_by_field_name("name")
                if (
                    name_node
                    and source[name_node.start_byte : name_node.end_byte].decode("utf-8")
                    == prop_name
                ):
                    return child.child_by_field_name("default_value")
    for child in node.children:
        res = _find_property_declaration(child, prop_name, source)
        if res:
            return res
    return None


def _parse_app_groups(node: Node | None, source: bytes) -> dict[str, list[str]]:
    """
    Looks for:
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->api(prepend: [...], append: [...]);
        $middleware->web(append: [...]);
    })
    """
    groups: dict[str, list[str]] = {"api": [], "web": []}
    with_middleware_node = _find_method_call(node, "withMiddleware", source)
    if not with_middleware_node:
        return {}

    # Explore the closure body inside withMiddleware
    _explore_closure_for_groups(with_middleware_node, source, groups)

    # Clean up empty groups
    return {k: v for k, v in groups.items() if v}


def _find_method_call(node: Node | None, method_name: str, source: bytes) -> Node | None:
    if node is None:
        return None
    if node.type in ("method_invocation", "member_call_expression"):
        name_node = node.child_by_field_name("name")
        if (
            name_node
            and source[name_node.start_byte : name_node.end_byte].decode("utf-8") == method_name
        ):
            return node
    for child in node.children:
        res = _find_method_call(child, method_name, source)
        if res:
            return res
    return None


def _explore_closure_for_groups(
    node: Node | None, source: bytes, groups: dict[str, list[str]]
) -> None:
    if node is None:
        return
    # Find $middleware->api(...) or $middleware->web(...) calls
    if node.type == "member_call_expression":
        name_node = node.child_by_field_name("name")
        if name_node:
            name = source[name_node.start_byte : name_node.end_byte].decode("utf-8")
            if name in ("api", "web"):
                args_node = node.child_by_field_name("arguments")
                if args_node:
                    # In Laravel 11, it's typically named arguments: append: [...], prepend: [...]
                    for arg in args_node.children:
                        if arg.type == "argument":
                            # check if it's an array
                            # It could be `append: [...]`
                            array_node = None
                            for child in arg.children:
                                if child.type == "array_creation_expression":
                                    array_node = child
                                    break

                            if array_node:
                                for val_child in array_node.children:
                                    if val_child.type == "array_element_initializer":
                                        if len(val_child.children) >= 1:
                                            member = _extract_string(val_child.children[0], source)
                                            if member:
                                                # Order does not strictly matter for attack surface.
                                                # For now, just append to the list.
                                                groups[name].append(member)

    for child in node.children:
        _explore_closure_for_groups(child, source, groups)


_AUTH_MIDDLEWARE = frozenset({"auth", "password.confirm", "auth.basic", "auth:sanctum", "auth:api"})


def authenticated_by(route: Route) -> str | None:
    for name in route.middleware:
        if name.split(":", 1)[0] in _AUTH_MIDDLEWARE or name in _AUTH_MIDDLEWARE:
            return name
    return None


def is_authenticated(route: Route) -> bool:
    return authenticated_by(route) is not None


def is_guest(route: Route) -> bool:
    return any(name.split(":", 1)[0] == "guest" for name in route.middleware)


def is_verified(route: Route) -> bool:
    return any(name.split(":", 1)[0] == "verified" for name in route.middleware)


def is_signed(route: Route) -> bool:
    return any(name.split(":", 1)[0] == "signed" for name in route.middleware)


def is_rate_limited(route: Route) -> bool:
    return any(name.split(":", 1)[0] == "throttle" for name in route.middleware)


def is_gated(route: Route) -> bool:
    for name in route.middleware:
        if name == "?" or name.startswith("can:"):
            return True
    return False


def is_password_confirmed(route: Route) -> bool:
    return any(name.split(":", 1)[0] == "password.confirm" for name in route.middleware)


def middleware_sanitizes(name: str) -> frozenset[TaintKind]:
    """Which taint kinds this middleware globally sanitizes."""
    # TrimStrings and ConvertEmptyStringsToNull explicitly do not sanitize anything.
    if name in (
        "TrimStrings",
        "Illuminate\\Foundation\\Http\\Middleware\\TrimStrings",
        "ConvertEmptyStringsToNull",
        "Illuminate\\Foundation\\Http\\Middleware\\ConvertEmptyStringsToNull",
    ):
        return frozenset()

    return frozenset()
