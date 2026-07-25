"""Which controller data reaches which template.

Taint has to cross the view() call or an XSS finding cannot have a complete
evidence path, and a finding without a path is not a finding - see
docs/08-framework-adapters.

ponytail: the three common call forms only. @include, @extends and components
do not carry taint across template files in this slice, so taint stops at the
template it was handed to.
"""

from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from ..parser import find_all, node_text

_VIEW_ROOT = Path("resources/views")


@dataclass(frozen=True)
class ViewBinding:
    """A resolved view() call: the template, and what was handed to it."""

    template: str
    variables: dict[str, Node] = field(default_factory=dict)
    compacted: tuple[str, ...] = ()


def template_path(name: str) -> Path:
    """'orders.show' -> resources/views/orders/show.blade.php."""
    return _VIEW_ROOT / (name.replace(".", "/") + ".blade.php")


def _literal(node: Node, source: bytes) -> str | None:
    """The value of a string literal, or None if this is not one.

    Single quoted literals parse as `string` and double quoted ones as
    `encapsed_string`, so the value is read from the shared string_content
    child rather than by matching either node type.
    """
    if node.type not in ("string", "encapsed_string"):
        return None
    content = find_all(node, "string_content")
    return node_text(content[0], source) if content else ""


def _arguments(call: Node) -> list[Node]:
    args_node = call.child_by_field_name("arguments")
    if args_node is None:
        return []
    return [a for a in args_node.children if a.is_named]


def _unwrap(argument: Node) -> Node:
    """An `argument` node wraps the expression it carries."""
    named = [c for c in argument.children if c.is_named]
    return named[0] if named else argument


def extract_view_binding(stmt: Node, source: bytes) -> ViewBinding | None:
    """Resolve the view() call in this statement, if there is a resolvable one.

    Returns None when the statement has no view() call, or when the template
    name is computed rather than literal. The caller records the second case as
    a coverage gap; guessing at it would be worse than reporting it.
    """
    view_call = next(
        (
            c
            for c in find_all(stmt, "function_call_expression")
            if node_text(c.child_by_field_name("function"), source) == "view"
        ),
        None,
    )
    if view_call is None:
        return None

    args = _arguments(view_call)
    if not args:
        return None
    name = _literal(_unwrap(args[0]), source)
    if name is None:
        return None

    variables: dict[str, Node] = {}
    compacted: list[str] = []

    if len(args) > 1:
        data = _unwrap(args[1])
        if data.type == "array_creation_expression":
            for element in find_all(data, "array_element_initializer"):
                parts = [c for c in element.children if c.is_named]
                if len(parts) == 2:
                    key = _literal(parts[0], source)
                    if key is not None:
                        variables[key] = parts[1]
        elif (
            data.type == "function_call_expression"
            and node_text(data.child_by_field_name("function"), source) == "compact"
        ):
            for argument in _arguments(data):
                key = _literal(_unwrap(argument), source)
                if key:
                    compacted.append(key)

    # ->with('key', $value) chained onto the same statement.
    for call in find_all(stmt, "member_call_expression"):
        if node_text(call.child_by_field_name("name"), source) != "with":
            continue
        with_args = _arguments(call)
        if len(with_args) == 2:
            key = _literal(_unwrap(with_args[0]), source)
            if key:
                variables[key] = _unwrap(with_args[1])

    return ViewBinding(template=name, variables=variables, compacted=tuple(compacted))
