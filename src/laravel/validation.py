"""Laravel request validation rule parser and per-rule taint clearing map."""

from tree_sitter import Node

from ..models import ALL_KINDS, TaintKind
from ..parser import ParsedFile, find_all, node_text

# Taint kinds cleared by individual validation rules
_RULE_CLEARS: dict[str, frozenset[TaintKind]] = {
    "integer": frozenset({TaintKind.SQL}),
    "int": frozenset({TaintKind.SQL}),
    "numeric": frozenset({TaintKind.SQL}),
    "digits": frozenset({TaintKind.SQL}),
    "digits_between": frozenset({TaintKind.SQL}),
    "decimal": frozenset({TaintKind.SQL}),
    "boolean": frozenset({TaintKind.SQL}),
    "bool": frozenset({TaintKind.SQL}),
    "uuid": frozenset({TaintKind.SQL}),
    "ulid": frozenset({TaintKind.SQL}),
    "exists": frozenset({TaintKind.SQL}),
    "alpha": frozenset({TaintKind.SQL}),
    "alpha_num": frozenset({TaintKind.SQL}),
    "alpha_dash": frozenset({TaintKind.SQL}),
}


def rule_clears(rule_str: str) -> frozenset[TaintKind]:
    """Return the set of TaintKinds cleared by a single validation rule string."""
    rule_clean = rule_str.strip().lower()
    if not rule_clean:
        return frozenset()

    # in:a,b,c or Rule::in(...) clears all taint kinds
    if rule_clean == "in" or rule_clean.startswith("in:") or "rule::in" in rule_clean:
        return ALL_KINDS

    # exists:table,column clears SQL taint
    if rule_clean.startswith("exists:"):
        return frozenset({TaintKind.SQL})

    base_rule = rule_clean.split(":", 1)[0].strip()
    return _RULE_CLEARS.get(base_rule, frozenset())


def parse_rules_array(array_node: Node, source: bytes) -> dict[str, frozenset[TaintKind]]:
    """Parse an array creation expression node representing validation rules:

    ['id' => 'required|integer', 'name' => ['required', 'string']]
    Returns field_name -> set of cleared TaintKinds.
    """
    cleared_map: dict[str, frozenset[TaintKind]] = {}
    if array_node.type != "array_creation_expression":
        return cleared_map

    for element in array_node.children:
        if element.type != "array_element_initializer":
            continue

        children = [c for c in element.children if c.type not in ("=>", ",")]
        if len(children) < 2:
            continue

        key_node, val_node = children[0], children[1]
        field_name = node_text(key_node, source).strip("'\"")
        if not field_name:
            continue

        field_cleared: set[TaintKind] = set()

        if val_node.type == "string":
            raw_val = node_text(val_node, source).strip("'\"")
            for sub_rule in raw_val.split("|"):
                field_cleared.update(rule_clears(sub_rule))
        elif val_node.type == "array_creation_expression":
            for item in val_node.children:
                if item.type in (
                    "array_element_initializer",
                    "string",
                    "scoped_call_expression",
                    "call_expression",
                ):
                    raw_val = node_text(item, source).strip("'\"")
                    field_cleared.update(rule_clears(raw_val))
        else:
            raw_val = node_text(val_node, source).strip("'\"")
            field_cleared.update(rule_clears(raw_val))

        cleared_map[field_name] = frozenset(field_cleared)

    return cleared_map


def extract_validation_cleared(
    method_node: Node, source: bytes, _parsed_file: ParsedFile | None = None
) -> dict[str, frozenset[TaintKind]]:
    """Extract validation rules inside a method node.

    Returns field_name -> set of cleared TaintKinds.
    """
    cleared_map: dict[str, set[TaintKind]] = {}

    # 1. Look for $request->validate(['id' => ...]) or $this->validate($request, ['id' => ...])
    for member_call in find_all(method_node, "member_call_expression"):
        name_node = member_call.child_by_field_name("name")
        if name_node is None:
            continue
        method_name = node_text(name_node, source)
        if method_name != "validate":
            continue

        args_node = member_call.child_by_field_name("arguments")
        if args_node is None:
            continue

        real_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
        for arg in real_args:
            arr_nodes = find_all(arg, "array_creation_expression")
            if arr_nodes:
                rules = parse_rules_array(arr_nodes[0], source)
                for f_name, f_cleared in rules.items():
                    cleared_map.setdefault(f_name, set()).update(f_cleared)

    # 2. Look for Validator::make(..., ['id' => ...])
    for scoped_call in find_all(method_node, "scoped_call_expression"):
        scope_node = scoped_call.child_by_field_name("scope")
        name_node = scoped_call.child_by_field_name("name")
        if scope_node is None or name_node is None:
            continue
        scope_name = node_text(scope_node, source)
        name = node_text(name_node, source)
        if scope_name == "Validator" and name == "make":
            args_node = scoped_call.child_by_field_name("arguments")
            if args_node is not None:
                real_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if len(real_args) >= 2:
                    arr_nodes = find_all(real_args[1], "array_creation_expression")
                    if arr_nodes:
                        rules = parse_rules_array(arr_nodes[0], source)
                        for f_name, f_cleared in rules.items():
                            cleared_map.setdefault(f_name, set()).update(f_cleared)

    return {k: frozenset(v) for k, v in cleared_map.items()}
