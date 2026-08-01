"""Symbol table construction: namespaces, imports, classes, methods, properties."""

from dataclasses import dataclass, field

from tree_sitter import Node

from .models import Span, Symbol
from .parser import ParsedFile, find_all, find_any, node_span, node_text

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
    traits: tuple[str, ...] = ()
    # Alias -> (trait FQN, original method). The trait is empty only for an
    # unqualified adaptation over several traits; Project resolves that form
    # only when exactly one used trait provides the method.
    trait_aliases: dict[str, tuple[str, str]] = field(default_factory=dict)
    # Method -> the traits `insteadof` excludes for it. Exclusions, not a
    # winner, because that is what PHP's construct says: `A::run insteadof B`
    # removes B's copy and says nothing about a third trait, so a class using
    # A, B and C still has a real collision on `run`. Recording the left-hand
    # side as "the winner" would resolve that invalid class to A, and would
    # make the result depend on the order the clauses happened to be written.
    trait_exclusions: dict[str, frozenset[str]] = field(default_factory=dict)
    # Methods declared without a body: `abstract function f();` in a class or a
    # trait. A requirement, never an implementation - PHP dispatches such a
    # call to whichever composed trait or ancestor supplies the body, so
    # resolution must look past it rather than stop on it. Stopping would point
    # the call graph at a bodyless declaration and silently end a taint walk,
    # which is a false negative dressed as a resolved call.
    abstract_methods: set[str] = field(default_factory=set)
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
    traits: dict[str, ClassInfo] = field(default_factory=dict)


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


def resolve_type_name(
    type_name: str,
    namespace: str,
    imports: dict[str, str],
    autoload_roots: frozenset[str] = frozenset(),
) -> str:
    """Resolve a written type name to a fully qualified name.

    Only class-like names get namespace resolution. Scalar/builtin type
    hints (string, int, self, ...) and union/intersection types are not
    class names and must be returned unchanged, otherwise a promoted
    parameter like `private int $perPage` would be recorded as a bogus
    class property.

    `autoload_roots` is the set of PSR-4 namespace prefixes `composer.json`
    declares, each ending in a backslash. A qualified name that begins with one
    of them - `App\\Models\\User` where `App\\` is autoloaded - is already
    fully qualified and is returned unchanged, which is step 1 of docs/03-parser
    section Discovery and the reason such a name resolves at all with no `use`
    statement above it. This module never sees `composer.json`: it is handed the
    prefixes as plain data, because a parser that knew about Composer would be
    the layering violation CLAUDE.md warns about.

    Order matters and follows PHP's own. An import alias wins over an autoload
    root, because `use Other\\Thing as App;` genuinely rebinds `App` for this
    file, and only names that no `use` statement claims reach the autoload set.

    ponytail: the ceiling is a class whose own name repeats an autoloaded root,
    `App\\App\\Models\\User` referenced from inside `namespace App;`. PHP would
    read the written `App\\Models\\User` there as namespace-relative and so does
    Composer, and this returns the autoloadable name instead. Resolving it needs
    the answer to "is this FQN a class the project defines", which lives in
    `Project`, not here; the upgrade trigger is a resolver that has the class
    table to hand and can prefer the namespace-relative reading when it names a
    class that actually exists.
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
    if any(type_name.startswith(root) for root in autoload_roots):
        return type_name
    if namespace:
        return f"{namespace}\\{type_name}"
    return type_name


def _base_class(
    cls: Node,
    source: bytes,
    namespace: str,
    imports: dict[str, str],
    autoload_roots: frozenset[str],
) -> str | None:
    """The resolved FQN of the class this one extends, if any.

    class_declaration has no `base_clause` field, so the child is found by
    type. Verified against the grammar rather than assumed.
    """
    for child in cls.children:
        if child.type == "base_clause":
            for name in child.children:
                if name.type in ("name", "qualified_name"):
                    return resolve_type_name(
                        node_text(name, source), namespace, imports, autoload_roots
                    )
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


def _direct_children(node: Node, type_name: str) -> list[Node]:
    """Named children of `node` with one type, without descending into nested types."""
    return [child for child in node.named_children if child.type == type_name]


def _type_body(declaration: Node) -> Node | None:
    return declaration.child_by_field_name("body")


def _trait_reference(node: Node, source: bytes) -> tuple[str, str]:
    """The optional trait and method named by one adaptation reference."""
    if node.type == "class_constant_access_expression":
        names = [child for child in node.named_children if child.type in ("name", "qualified_name")]
        if len(names) >= 2:
            return node_text(names[0], source), node_text(names[1], source)
    if node.type in ("name", "qualified_name"):
        return "", node_text(node, source)
    return "", ""


def _adaptation_names(node: Node, source: bytes) -> list[str]:
    """Every trait name written on the right-hand side of one adaptation clause.

    ponytail: the installed tree-sitter-php grammar has no rule for the comma list in
    `A::run insteadof B, C`, so it parses the first losing trait into an `ERROR` node and
    leaves the rest as siblings. The names are all still there and are read from both
    places, because reading only the siblings would silently drop `B` and turn a class
    the author fully disambiguated into a reported collision. The file is separately
    recorded as a parse failure by `error_constructs`, so the coverage report already
    says the grammar could not read it (invariant 4). Upgrade trigger: a grammar release
    with the rule, after which the ERROR branch stops matching and can go.
    """
    if node.type in ("name", "qualified_name"):
        return [node_text(node, source)]
    if node.type == "ERROR":
        return [
            node_text(child, source)
            for child in node.named_children
            if child.type in ("name", "qualified_name")
        ]
    return []


def _trait_uses(
    declaration: Node,
    source: bytes,
    namespace: str,
    imports: dict[str, str],
    autoload_roots: frozenset[str],
) -> tuple[tuple[str, ...], dict[str, tuple[str, str]], dict[str, frozenset[str]]]:
    """Traits and adaptations declared directly in a class or trait body.

    Only `use_declaration` children of this body are read, so a nested class or
    trait declared in the same file contributes nothing here.
    """
    body = _type_body(declaration)
    if body is None:
        return (), {}, {}

    used: list[str] = []
    aliases: dict[str, tuple[str, str]] = {}
    exclusions: dict[str, frozenset[str]] = {}

    for use in _direct_children(body, "use_declaration"):
        for child in use.named_children:
            if child.type in ("name", "qualified_name"):
                used.append(
                    resolve_type_name(node_text(child, source), namespace, imports, autoload_roots)
                )

        lists = _direct_children(use, "use_list")
        if not lists:
            continue
        for clause in lists[0].named_children:
            if clause.type == "use_instead_of_clause":
                named = list(clause.named_children)
                if not named:
                    continue
                _, method = _trait_reference(named[0], source)
                if not method:
                    continue
                # `A::run insteadof B, C` names every losing trait, so all of them are
                # collected. Only the named traits lose; a trait no clause mentions is
                # still a live copy, which is what keeps a genuine collision visible.
                losing = {
                    resolve_type_name(written, namespace, imports, autoload_roots)
                    for child in named[1:]
                    for written in _adaptation_names(child, source)
                }
                if losing:
                    exclusions[method] = exclusions.get(method, frozenset()) | losing
            elif clause.type == "use_as_clause":
                named = list(clause.named_children)
                if not named:
                    continue
                trait, method = _trait_reference(named[0], source)
                # `Shared::work as protected;` only changes visibility and
                # introduces no second name, and the grammar gives that clause a
                # `visibility_modifier` rather than a `name`. Filtering on the
                # node type is what keeps it from being read as an alias called
                # `protected`.
                aliases_found = [child for child in named[1:] if child.type == "name"]
                if not method or not aliases_found:
                    continue
                alias = node_text(aliases_found[-1], source)
                resolved_trait = (
                    resolve_type_name(trait, namespace, imports, autoload_roots)
                    if trait
                    else (used[0] if len(used) == 1 else "")
                )
                aliases[alias] = (resolved_trait, method)

    return tuple(used), aliases, exclusions


def _extract_type(
    declaration: Node,
    parsed: ParsedFile,
    namespace: str,
    imports: dict[str, str],
    autoload_roots: frozenset[str],
    *,
    is_trait: bool,
) -> ClassInfo | None:
    """Extract one class-like declaration without absorbing nested declarations."""
    source = parsed.source
    name_node = declaration.child_by_field_name("name")
    if name_node is None:
        return None
    short = node_text(name_node, source)
    fqn = f"{namespace}\\{short}" if namespace else short
    traits, aliases, exclusions = _trait_uses(
        declaration, source, namespace, imports, autoload_roots
    )
    info = ClassInfo(
        fqn=fqn,
        span=node_span(declaration, parsed.path),
        parent=(
            None
            if is_trait
            else _base_class(declaration, source, namespace, imports, autoload_roots)
        ),
        traits=traits,
        trait_aliases=aliases,
        trait_exclusions=exclusions,
    )
    body = _type_body(declaration)
    if body is None:
        return info

    for method in _direct_children(body, "method_declaration"):
        m_name_node = method.child_by_field_name("name")
        if m_name_node is None:
            continue
        m_name = node_text(m_name_node, source)
        names, types = _params(method, source)
        if method.child_by_field_name("body") is None:
            info.abstract_methods.add(m_name)
        info.methods[m_name] = Symbol(
            fqn=f"{fqn}::{m_name}",
            kind="method",
            span=node_span(method, parsed.path),
            params=names,
            param_types=tuple(
                resolve_type_name(t, namespace, imports, autoload_roots) if t else None
                for t in types
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
                    info.properties[p_name] = resolve_type_name(
                        p_type, namespace, imports, autoload_roots
                    )

    # Explicitly declared typed properties, plus the array defaults the
    # framework-structural rules read.
    for prop in _direct_children(body, "property_declaration"):
        type_node = prop.child_by_field_name("type")
        for element in find_all(prop, "property_element"):
            p_name = node_text(element, source).split("=")[0].strip().lstrip("$")
            if not p_name:
                continue
            if type_node is not None:
                info.properties[p_name] = resolve_type_name(
                    node_text(type_node, source), namespace, imports, autoload_roots
                )
            default = element.child_by_field_name("default_value")
            if default is not None and default.type == "array_creation_expression":
                values = array_literal(default, source)
                if values is not None:
                    info.array_props[p_name] = values
                    info.array_prop_spans[p_name] = node_span(prop, parsed.path)

    return info


def extract_symbols(
    parsed: ParsedFile, autoload_roots: frozenset[str] = frozenset()
) -> FileSymbols:
    """The symbol table for one file.

    `autoload_roots` are the project's PSR-4 namespace prefixes, from
    `vigilloo.laravel.detect`; see `resolve_type_name` for what they change.
    They default to empty so that a caller holding a single file and no project
    - the parser tests, and anything reasoning about one file in isolation -
    still gets file-local resolution rather than needing a `composer.json`.
    """
    root = parsed.tree.root_node
    source = parsed.source
    namespace = _namespace(root, source)
    imports = _imports(root, source)
    classes: dict[str, ClassInfo] = {}
    traits: dict[str, ClassInfo] = {}

    # Enums are extracted as classes, and belong in the same table rather than a
    # third one beside `traits`. A method on an enum has a body, takes parameters
    # and can reach a sink, so to everything downstream - method lookup, the call
    # graph, the taint walk - an enum is a type with methods and nothing about it
    # needs a special case. Leaving them out was not a partial answer but a silent
    # one: the type did not exist, so a call into it resolved to nothing and the
    # walk stopped without even counting the call as unresolved.
    #
    # `_extract_type` needs no change to read one. The grammar gives
    # enum_declaration the same `name` and `body` fields, and hangs its methods
    # off the body as direct children exactly as a class does; `enum_case` children
    # are simply not method_declarations and are skipped. An enum has no
    # `base_clause` - `enum Status: string` is a backing type, not a parent - so
    # the parent it records is None, which is the truth rather than a default.
    for declaration in find_any(root, ("class_declaration", "enum_declaration")):
        info = _extract_type(
            declaration, parsed, namespace, imports, autoload_roots, is_trait=False
        )
        if info is not None:
            classes[info.fqn] = info

    for trait in find_all(root, "trait_declaration"):
        info = _extract_type(trait, parsed, namespace, imports, autoload_roots, is_trait=True)
        if info is not None:
            traits[info.fqn] = info

    return FileSymbols(namespace=namespace, imports=imports, classes=classes, traits=traits)
