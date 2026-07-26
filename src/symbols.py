"""Symbol table construction: namespaces, imports, classes, methods, properties."""

from dataclasses import dataclass, field

from tree_sitter import Node

from .models import Span, Symbol
from .parser import ParsedFile, find_all, node_span, node_text

_BUILTIN_TYPES = frozenset(
    {
        "string",
        "int",
        "float",
        "bool",
        "array",
        "object",
        "mixed",
        "callable",
        "iterable",
        "void",
        "null",
        "never",
        "false",
        "true",
        "self",
        "static",
        "parent",
    }
)


@dataclass(frozen=True)
class ClassInfo:
    fqn: str
    span: Span
    methods: dict[str, Symbol] = field(default_factory=dict)
    properties: dict[str, str] = field(default_factory=dict)
    parent: str | None = None
    # Property name -> the string literals of its array default, for the
    # framework-structural rules that read model configuration ($fillable,
    # $guarded). A property whose array holds anything the extractor cannot
    # read as a literal is absent rather than recorded short: "$guarded is an
    # empty array" and "$guarded is an array I could not read" mean opposite
    # things to the mass-assignment rule, and conflating them reports every
    # model in the codebase.
    array_props: dict[str, tuple[str, ...]] = field(default_factory=dict)
    array_prop_spans: dict[str, Span] = field(default_factory=dict)


@dataclass(frozen=True)
class FileSymbols:
    namespace: str
    imports: dict[str, str]
    classes: dict[str, ClassInfo]


def _namespace(root: Node, source: bytes) -> str:
    for node in find_all(root, "namespace_definition"):
        name = node.child_by_field_name("name")
        if name is not None:
            return node_text(name, source)
    return ""


def _imports(root: Node, source: bytes) -> dict[str, str]:
    """Map short name (or alias) to fully qualified name."""
    imports: dict[str, str] = {}
    for node in find_all(root, "namespace_use_declaration"):
        for clause in find_all(node, "namespace_use_clause"):
            text = node_text(clause, source).strip()
            if " as " in text:
                fqn, alias = (p.strip() for p in text.split(" as ", 1))
            else:
                fqn, alias = text, text.rsplit("\\", 1)[-1]
            imports[alias] = fqn.lstrip("\\")
    return imports


def resolve_type_name(type_name: str, namespace: str, imports: dict[str, str]) -> str:
    """Resolve a written type name to a fully qualified name.

    Only class-like names get namespace resolution. Scalar/builtin type
    hints (string, int, self, ...) and union/intersection types are not
    class names and must be returned unchanged, otherwise a promoted
    parameter like `private int $perPage` would be recorded as a bogus
    class property.
    """
    type_name = type_name.strip().lstrip("?")
    if not type_name:
        return ""
    if "|" in type_name or "&" in type_name:
        return type_name
    if type_name.lower() in _BUILTIN_TYPES:
        return type_name.lower()
    if type_name.startswith("\\"):
        return type_name.lstrip("\\")
    head, _, rest = type_name.partition("\\")
    if head in imports:
        return f"{imports[head]}\\{rest}" if rest else imports[head]
    if namespace:
        return f"{namespace}\\{type_name}"
    return type_name


def _base_class(cls: Node, source: bytes, namespace: str, imports: dict[str, str]) -> str | None:
    """The resolved FQN of the class this one extends, if any.

    class_declaration has no `base_clause` field, so the child is found by
    type. Verified against the grammar rather than assumed.
    """
    for child in cls.children:
        if child.type == "base_clause":
            for name in child.children:
                if name.type in ("name", "qualified_name"):
                    return resolve_type_name(node_text(name, source), namespace, imports)
    return None


def array_literal(node: Node, source: bytes) -> tuple[str, ...] | None:
    """The string literals in an array literal, or None if it holds anything else.

    None means "unreadable", which callers must not confuse with an empty
    tuple. `$guarded = []` disables mass-assignment protection entirely;
    `$guarded = [self::LOCKED]` does not, and reading the second as the first
    would fire on a correctly configured model.
    """
    values: list[str] = []
    for element in node.children:
        if element.type != "array_element_initializer":
            continue
        text = node_text(element, source).strip()
        if len(text) >= 2 and text[0] in "'\"" and text[-1] == text[0]:
            values.append(text[1:-1])
        else:
            return None
    return tuple(values)


def _params(method: Node, source: bytes) -> tuple[tuple[str, ...], tuple[str | None, ...]]:
    names: list[str] = []
    types: list[str | None] = []
    params_node = method.child_by_field_name("parameters")
    if params_node is None:
        return (), ()
    for child in params_node.children:
        if child.type not in ("simple_parameter", "property_promotion_parameter"):
            continue
        name_node = child.child_by_field_name("name")
        type_node = child.child_by_field_name("type")
        names.append(node_text(name_node, source).lstrip("$"))
        types.append(node_text(type_node, source) if type_node is not None else None)
    return tuple(names), tuple(types)


def extract_symbols(parsed: ParsedFile) -> FileSymbols:
    root = parsed.tree.root_node
    source = parsed.source
    namespace = _namespace(root, source)
    imports = _imports(root, source)
    classes: dict[str, ClassInfo] = {}

    for cls in find_all(root, "class_declaration"):
        name_node = cls.child_by_field_name("name")
        if name_node is None:
            continue
        short = node_text(name_node, source)
        fqn = f"{namespace}\\{short}" if namespace else short
        info = ClassInfo(
            fqn=fqn,
            span=node_span(cls, parsed.path),
            parent=_base_class(cls, source, namespace, imports),
        )

        for method in find_all(cls, "method_declaration"):
            m_name_node = method.child_by_field_name("name")
            if m_name_node is None:
                continue
            m_name = node_text(m_name_node, source)
            names, types = _params(method, source)
            info.methods[m_name] = Symbol(
                fqn=f"{fqn}::{m_name}",
                kind="method",
                span=node_span(method, parsed.path),
                params=names,
                param_types=tuple(
                    resolve_type_name(t, namespace, imports) if t else None for t in types
                ),
            )
            # PHP 8 constructor property promotion declares a property and a
            # parameter in one place. Capturing it here is what lets a later
            # layer resolve $this->prop->method() to a concrete class.
            params_node = method.child_by_field_name("parameters")
            if params_node is not None:
                for promoted in find_all(params_node, "property_promotion_parameter"):
                    p_name = node_text(promoted.child_by_field_name("name"), source).lstrip("$")
                    p_type = node_text(promoted.child_by_field_name("type"), source)
                    if p_name and p_type:
                        info.properties[p_name] = resolve_type_name(p_type, namespace, imports)

        # Explicitly declared typed properties, plus the array defaults the
        # framework-structural rules read. An untyped `protected $guarded = []`
        # has no type node at all, which is why it needs its own branch here
        # rather than falling out of the typed-property loop.
        for prop in find_all(cls, "property_declaration"):
            type_node = prop.child_by_field_name("type")
            for element in find_all(prop, "property_element"):
                p_name = node_text(element, source).split("=")[0].strip().lstrip("$")
                if not p_name:
                    continue
                if type_node is not None:
                    info.properties[p_name] = resolve_type_name(
                        node_text(type_node, source), namespace, imports
                    )
                default = element.child_by_field_name("default_value")
                if default is not None and default.type == "array_creation_expression":
                    values = array_literal(default, source)
                    if values is not None:
                        info.array_props[p_name] = values
                        info.array_prop_spans[p_name] = node_span(prop, parsed.path)

        classes[fqn] = info

    return FileSymbols(namespace=namespace, imports=imports, classes=classes)
