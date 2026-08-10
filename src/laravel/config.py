"""Configuration and environment fact extraction.

Parses config/*.php files with their env() defaults, .env, and .env.example,
storing values in a ProjectConfig fact object while ensuring secrets and
sensitive credentials are NEVER exposed in plain text.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tree_sitter import Node

from ..parser import ParsedFile, find_all, node_text

_SECRET_PATTERNS = {
    "SECRET",
    "PASSWORD",
    "PASS",
    "TOKEN",
    "CREDENTIAL",
    "PRIVATE_KEY",
    "AWS_SECRET",
    "STRIPE_SECRET",
    "DB_PASSWORD",
    "APP_KEY",
}


def is_secret_key(key: str) -> bool:
    upper = key.upper()
    return any(pattern in upper for pattern in _SECRET_PATTERNS)


@dataclass(frozen=True)
class ConfigValue:
    key: str
    value: Any
    env_var: str | None = None
    default_value: Any = None
    file_path: Path | None = None
    is_secret: bool = False

    @property
    def safe_value(self) -> Any:
        if self.is_secret and self.value is not None:
            return "[REDACTED]"
        return self.value


@dataclass(frozen=True)
class ProjectConfig:
    values: dict[str, ConfigValue] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    env_file_exists: bool = False
    env_example_exists: bool = False

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.values:
            return self.values[key].value
        return default

    def get_value_object(self, key: str) -> ConfigValue | None:
        return self.values.get(key)


def parse_env_file(env_path: Path) -> dict[str, str]:
    """Parse a .env or .env.example file into key-value pairs."""
    env_vars: dict[str, str] = {}
    if not env_path.is_file():
        return env_vars

    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError:
        return env_vars

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()

        # Strip surrounding quotes if matching
        if len(val) >= 2 and (
            (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")
        ):
            val = val[1:-1]

        if key:
            env_vars[key] = val

    return env_vars


def _parse_php_literal(node: Node, source: bytes) -> Any:
    """Parse basic PHP AST literal nodes into Python values."""
    text = node_text(node, source).strip()
    if len(text) >= 2 and (
        (text[0] == '"' and text[-1] == '"') or (text[0] == "'" and text[-1] == "'")
    ):
        text = text[1:-1]

    if node.type in ("integer", "number"):
        try:
            return int(text)
        except ValueError:
            try:
                return float(text)
            except ValueError:
                return text
    if node.type == "boolean_literal":
        return text.lower() == "true"
    if node.type in ("null", "null_literal"):
        return None
    if node.type == "cast_expression":
        child = node.child_by_field_name("value")
        if child:
            val = _parse_php_literal(child, source)
            cast_type = node_text(node.children[0], source).lower().strip("()")
            if cast_type in ("bool", "boolean"):
                if isinstance(val, str):
                    return val.lower() in ("true", "1")
                return bool(val)
            if cast_type in ("int", "integer"):
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return 0
            return val
    return text


def _eval_expr(
    node: Node,
    source: bytes,
    env_vars: dict[str, str],
) -> tuple[Any, str | None, Any]:
    """Returns (resolved_value, env_var_name, default_value)."""
    if node.type == "cast_expression":
        child = node.child_by_field_name("value")
        if child:
            val, env_var, default_val = _eval_expr(child, source, env_vars)
            cast_type = node_text(node.children[0], source).lower().strip("()")
            if cast_type in ("bool", "boolean"):
                if isinstance(val, str):
                    val = val.lower() in ("true", "1")
                else:
                    val = bool(val)
            elif cast_type in ("int", "integer"):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    val = 0
            return val, env_var, default_val

    if node.type == "function_call_expression":
        fn_name = node_text(node.child_by_field_name("function"), source)
        if fn_name == "env":
            args_node = node.child_by_field_name("arguments")
            if args_node:
                args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                if args:
                    var_name_val = _parse_php_literal(args[0], source)
                    var_name = str(var_name_val) if var_name_val is not None else None
                    default_val = None
                    if len(args) > 1:
                        default_val, _, _ = _eval_expr(args[1], source, env_vars)

                    resolved_val = default_val
                    if var_name and var_name in env_vars:
                        raw_str = env_vars[var_name]
                        if raw_str.lower() == "true":
                            resolved_val = True
                        elif raw_str.lower() == "false":
                            resolved_val = False
                        elif raw_str.lower() in ("null", "(null)"):
                            resolved_val = None
                        else:
                            try:
                                resolved_val = int(raw_str)
                            except ValueError:
                                resolved_val = raw_str

                    return resolved_val, var_name, default_val

    return _parse_php_literal(node, source), None, None


def extract_config_values(
    array_node: Node,
    source: bytes,
    file_path: Path,
    prefix: str,
    env_vars: dict[str, str],
) -> dict[str, ConfigValue]:
    """Recursively parse array_creation_expression nodes in a config file."""
    results: dict[str, ConfigValue] = {}

    for elem in array_node.children:
        if elem.type != "array_element_initializer":
            continue

        key_node = elem.child_by_field_name("key")
        val_node = elem.child_by_field_name("value")

        if key_node is None or val_node is None:
            # Fall back to finding => in children
            arrow_idx = -1
            for i, child in enumerate(elem.children):
                if child.type == "=>" or node_text(child, source) == "=>":
                    arrow_idx = i
                    break
            if arrow_idx > 0 and arrow_idx + 1 < len(elem.children):
                key_node = elem.children[arrow_idx - 1]
                val_node = elem.children[arrow_idx + 1]

        if key_node is None or val_node is None:
            continue

        key_str = str(_parse_php_literal(key_node, source))
        full_key = f"{prefix}.{key_str}" if prefix else key_str

        if val_node.type == "array_creation_expression":
            nested = extract_config_values(val_node, source, file_path, full_key, env_vars)
            results.update(nested)
        else:
            resolved_val, env_var, default_val = _eval_expr(val_node, source, env_vars)
            secret = is_secret_key(full_key) or (env_var is not None and is_secret_key(env_var))

            results[full_key] = ConfigValue(
                key=full_key,
                value=resolved_val,
                env_var=env_var,
                default_value=default_val,
                file_path=file_path,
                is_secret=secret,
            )

    return results


def extract_project_config(
    root_path: Path,
    files: dict[Path, ParsedFile],
) -> ProjectConfig:
    """Extract configuration and environment facts for a project."""
    env_file = root_path / ".env"
    env_example = root_path / ".env.example"

    env_file_exists = env_file.is_file()
    env_example_exists = env_example.is_file()

    env_vars = parse_env_file(env_file)
    if not env_vars and env_example_exists:
        env_vars = parse_env_file(env_example)

    config_values: dict[str, ConfigValue] = {}

    for rel_path, parsed in files.items():
        parts = rel_path.parts
        if len(parts) >= 2 and parts[0] == "config" and rel_path.suffix == ".php":
            prefix = rel_path.stem
            for ret_stmt in find_all(parsed.tree.root_node, "return_statement"):
                for arr_node in find_all(ret_stmt, "array_creation_expression"):
                    file_vals = extract_config_values(
                        arr_node,
                        parsed.source,
                        rel_path,
                        prefix,
                        env_vars,
                    )
                    config_values.update(file_vals)

    return ProjectConfig(
        values=config_values,
        env_vars=env_vars,
        env_file_exists=env_file_exists,
        env_example_exists=env_example_exists,
    )
