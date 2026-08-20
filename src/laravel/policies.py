"""Which policy class Laravel would use to authorize a given model.

Discovery reads AuthServiceProvider::$policies and Gate::policy() calls first,
falling back to Laravel's naming convention auto-discovery (App\\Models\\Order -> OrderPolicy).
"""

from collections.abc import Callable
from pathlib import Path

from tree_sitter import Node

from ..parser import ParsedFile, find_all, node_text
from ..symbols import ClassInfo


def _resolve_class_or_string(
    node: Node,
    source: bytes,
    path: Path,
    resolve_fn: Callable[[Path, str], str | None] | None = None,
) -> str | None:
    """Extract a class FQN from a string literal or a ClassName::class expression."""
    text = node_text(node, source).strip()
    if text.startswith(("'\"", "'", '"')):
        return text.strip("'\"").lstrip("\\")

    if text.endswith("::class"):
        class_name = text[:-7].strip().lstrip("\\")
        if resolve_fn is not None:
            resolved = resolve_fn(path, class_name)
            if resolved is not None:
                return resolved
        return class_name

    cleaned = text.lstrip("\\")
    if resolve_fn is not None:
        resolved = resolve_fn(path, cleaned)
        if resolved is not None:
            return resolved
    return cleaned


def extract_explicit_policies(
    properties_by_file: dict[Path, list[Node]],
    scoped_calls_by_file: dict[Path, list[Node]],
    files: dict[Path, ParsedFile],
    resolve_fn: Callable[[Path, str], str | None] | None = None,
) -> dict[str, str]:
    """Extract explicit model_fqn -> policy_fqn mappings from AuthServiceProvider or
    Gate::policy calls.
    """
    policies: dict[str, str] = {}

    for path, parsed in files.items():
        source = parsed.source
        # 1. Property `$policies = [...]`
        for prop in properties_by_file.get(path, []):
            name_node = prop.child_by_field_name("name")
            if name_node is None or node_text(name_node, source) != "$policies":
                continue

            default_val = prop.child_by_field_name("default_value")
            if default_val is None:
                continue

            arr_nodes = find_all(default_val, "array_creation_expression")
            if not arr_nodes:
                continue

            for elem in arr_nodes[0].children:
                if elem.type != "array_element_initializer":
                    continue
                children = [c for c in elem.children if c.type not in ("=>", ",")]
                if len(children) < 2:
                    continue

                key_node, val_node = children[0], children[1]
                model_fqn = _resolve_class_or_string(key_node, source, path, resolve_fn)
                policy_fqn = _resolve_class_or_string(val_node, source, path, resolve_fn)

                if model_fqn and policy_fqn:
                    policies[model_fqn] = policy_fqn

        # 2. Gate::policy(Model::class, Policy::class)
        for scoped in scoped_calls_by_file.get(path, []):
            scope_node = scoped.child_by_field_name("scope")
            method_node = scoped.child_by_field_name("name")
            if scope_node is None or method_node is None:
                continue

            scope_name = node_text(scope_node, source).rsplit("\\", 1)[-1]
            method_name = node_text(method_node, source)

            if scope_name == "Gate" and method_name == "policy":
                args_node = scoped.child_by_field_name("arguments")
                if args_node is None:
                    continue
                real_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if len(real_args) >= 2:
                    model_fqn = _resolve_class_or_string(real_args[0], source, path, resolve_fn)
                    policy_fqn = _resolve_class_or_string(real_args[1], source, path, resolve_fn)
                    if model_fqn and policy_fqn:
                        policies[model_fqn] = policy_fqn

    return policies


def find_policy(
    classes: dict[str, ClassInfo],
    model_fqn: str,
    explicit_map: dict[str, str] | None = None,
) -> str | None:
    """The FQN of the policy class for this model, if the project defines one.

    Checks explicit_map (AuthServiceProvider::$policies, Gate::policy) first,
    then falls back to naming convention auto-discovery.
    """
    if explicit_map and model_fqn in explicit_map:
        policy_fqn = explicit_map[model_fqn]
        if policy_fqn in classes:
            return policy_fqn
        for fqn in sorted(classes):
            if fqn == policy_fqn or fqn.rsplit("\\", 1)[-1] == policy_fqn.rsplit("\\", 1)[-1]:
                return fqn
        return policy_fqn

    wanted = f"{model_fqn.rsplit('\\', 1)[-1]}Policy"
    for fqn in sorted(classes):
        if fqn.rsplit("\\", 1)[-1] == wanted:
            return fqn
    return None
