"""Which controller data reaches which template.

Taint has to cross the view() call or an XSS finding cannot have a complete
evidence path, and a finding without a path is not a finding - see
docs/08-framework-adapters.

ponytail: the three common call forms only. @include, @extends and components
do not carry taint across template files in this slice, so taint stops at the
template it was handed to.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from tree_sitter import Node

from ..parser import find_all, node_text

_VIEW_ROOT = Path("resources/views")

# One segment of a dotted template name. Deliberately strict: names are read
# out of the analysed codebase, which is untrusted input, and a segment like
# ".." or one containing a slash would walk the built path out of
# resources/views.
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class ViewBinding:
    """A view() call: the template, and what was handed to it.

    template is None when the call is real but its name could not be resolved
    to a literal, e.g. view($name, ...). The binding is still returned rather
    than dropped, so the caller can see the call happened and record the gap
    instead of it vanishing - see docs/06-taint-analysis and invariant 4.

    variables is a tuple of pairs rather than a dict so the record is really
    immutable. Freezing a dataclass that holds a dict only freezes the
    reference, which is a guarantee in name only.
    """

    template: str | None
    variables: tuple[tuple[str, Node], ...] = ()
    compacted: tuple[str, ...] = ()


def template_path(name: str) -> Path | None:
    """'orders.show' -> resources/views/orders/show.blade.php.

    Returns None for anything that is not a plain dotted name. Path('a') / '/b'
    is '/b', because pathlib discards the base when the right side looks
    absolute, so an unchecked name beginning with a dot escapes the view root.
    """
    segments = name.split(".")
    if not all(_SEGMENT.fullmatch(segment) for segment in segments):
        return None
    return _VIEW_ROOT.joinpath(*segments[:-1], segments[-1] + ".blade.php")


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


def _chained_with(view_call: Node, source: bytes) -> list[tuple[str, Node]]:
    """Bindings from ->with('key', $value) chained onto this view() call.

    Walks up the parent chain rather than scanning the statement, because
    with() is also Eloquent's eager-loading method. A constrained eager load
    like $q->with('items', $callback) has exactly the same shape and would
    otherwise bind a template variable that does not exist.
    """
    pairs: list[tuple[str, Node]] = []
    node = view_call
    while True:
        parent = node.parent
        if parent is None or parent.type != "member_call_expression":
            return pairs
        receiver = parent.child_by_field_name("object")
        if receiver is None or receiver.id != node.id:
            return pairs
        if node_text(parent.child_by_field_name("name"), source) == "with":
            args = _arguments(parent)
            if len(args) == 2:
                key = _literal(_unwrap(args[0]), source)
                if key:
                    pairs.append((key, _unwrap(args[1])))
        node = parent


def extract_view_bindings(stmt: Node, source: bytes) -> list[ViewBinding]:
    """Every view() call in this statement.

    A statement can hold more than one, as in a ternary choosing between two
    templates. Returning all of them keeps the second from vanishing without
    a trace.

    A view() call whose template name is computed rather than literal still
    produces a binding, with template=None. Dropping it would let a real
    view() call disappear before the caller ever learns it existed, which is
    exactly the gap that makes coverage dishonest; guessing the name would be
    worse. The caller decides what an unresolved binding means for coverage.
    """
    bindings: list[ViewBinding] = []

    for call in find_all(stmt, "function_call_expression"):
        if node_text(call.child_by_field_name("function"), source) != "view":
            continue

        args = _arguments(call)
        if not args:
            continue
        name = _literal(_unwrap(args[0]), source)

        variables: list[tuple[str, Node]] = []
        compacted: list[str] = []

        if len(args) > 1:
            data = _unwrap(args[1])
            if data.type == "array_creation_expression":
                for element in find_all(data, "array_element_initializer"):
                    parts = [c for c in element.children if c.is_named]
                    if len(parts) == 2:
                        key = _literal(parts[0], source)
                        if key:
                            variables.append((key, parts[1]))
            elif (
                data.type == "function_call_expression"
                and node_text(data.child_by_field_name("function"), source) == "compact"
            ):
                for argument in _arguments(data):
                    key = _literal(_unwrap(argument), source)
                    if key:
                        compacted.append(key)

        variables.extend(_chained_with(call, source))
        bindings.append(
            ViewBinding(
                template=name,
                variables=tuple(variables),
                compacted=tuple(compacted),
            )
        )

    return bindings
