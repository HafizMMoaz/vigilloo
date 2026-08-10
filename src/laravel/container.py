"""Laravel Container binding resolution.

Extracts container bindings from `app()->bind()`, `singleton()`, and service provider
`register()` bodies, matching interfaces to their concrete implementations.
"""

from tree_sitter import Node

from ..parser import ParsedFile, find_all, node_text
from ..symbols import FileSymbols, resolve_type_name


def extract_bindings(
    parsed: ParsedFile, syms: FileSymbols, autoload_prefixes: frozenset[str]
) -> dict[str, list[str]]:
    """Extract interface-to-concrete mappings from container bindings.

    Returns a dictionary mapping the interface FQN to a list of concrete class FQNs.
    """
    bindings: dict[str, list[str]] = {}

    for call in find_all(parsed.tree.root_node, "member_call_expression"):
        method_name_node = call.child_by_field_name("name")
        if not method_name_node:
            continue
        method_name = node_text(method_name_node, parsed.source)
        if method_name not in ("bind", "singleton", "bindIf"):
            continue

        obj_node = call.child_by_field_name("object")
        if not obj_node:
            continue

        # Check if the object is $this->app or app()
        is_container = False
        if obj_node.type == "member_access_expression":
            inner_obj = obj_node.child_by_field_name("object")
            prop = obj_node.child_by_field_name("name")
            if (
                inner_obj
                and prop
                and node_text(inner_obj, parsed.source) == "$this"
                and node_text(prop, parsed.source) == "app"
            ):
                is_container = True
        elif obj_node.type == "function_call_expression":
            func_name = obj_node.child_by_field_name("name")
            if func_name and node_text(func_name, parsed.source) == "app":
                is_container = True

        if not is_container:
            continue

        args_node = call.child_by_field_name("arguments")
        if not args_node:
            continue

        args = [n for n in args_node.named_children if n.type == "argument"]
        if len(args) < 2:
            continue

        abstract_arg = args[0]
        concrete_arg = args[1]

        abstract_fqn = _resolve_arg(abstract_arg, parsed, syms, autoload_prefixes)
        concrete_fqn = _resolve_arg(concrete_arg, parsed, syms, autoload_prefixes)

        if abstract_fqn and concrete_fqn:
            bindings.setdefault(abstract_fqn, []).append(concrete_fqn)

    return bindings


def _resolve_arg(
    arg_node: Node, parsed: ParsedFile, syms: FileSymbols, autoload_prefixes: frozenset[str]
) -> str | None:
    # arg_node is an `argument` node. Its child is the actual expression.
    if not arg_node.children:
        return None

    expr = arg_node.named_children[0] if arg_node.named_children else None
    if not expr:
        return None

    if expr.type == "class_constant_access_expression":
        cls_node = expr.children[0]
        if cls_node:
            written = node_text(cls_node, parsed.source)
            return resolve_type_name(written, syms.namespace, syms.imports, autoload_prefixes)

    elif expr.type == "string":
        # e.g., 'App\\Services\\ReportService'
        val = node_text(expr, parsed.source)
        if val.startswith("'") and val.endswith("'"):
            val = val[1:-1].replace("\\\\", "\\")
        elif val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace("\\\\", "\\")
        if val:
            # If it's a string, it might already be an FQN or a simple string binding like 'reports'
            # We assume it's fully qualified if it has backslashes, else we leave it as is
            # because some bindings are bound by a simple string alias.
            return val

    return None
