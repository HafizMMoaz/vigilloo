"""Database migration parser for table schema extraction."""

from collections import defaultdict
from pathlib import Path

from tree_sitter import Node

from ..parser import ParsedFile, find_all, node_text

_COLUMN_METHODS: frozenset[str] = frozenset(
    {
        "bigIncrements",
        "bigInteger",
        "binary",
        "boolean",
        "char",
        "date",
        "dateTime",
        "dateTimeTz",
        "decimal",
        "double",
        "enum",
        "float",
        "foreignId",
        "foreignIdFor",
        "foreignUuid",
        "geometry",
        "geometryCollection",
        "id",
        "increments",
        "integer",
        "ipAddress",
        "json",
        "jsonb",
        "lineString",
        "longText",
        "macAddress",
        "mediumIncrements",
        "mediumInteger",
        "mediumText",
        "morphs",
        "nullableMorphs",
        "nullableTimestamps",
        "nullableUuidMorphs",
        "polygon",
        "rememberToken",
        "smallIncrements",
        "smallInteger",
        "softDeletes",
        "softDeletesTz",
        "string",
        "text",
        "time",
        "timeTz",
        "timestamp",
        "timestamps",
        "timestampsTz",
        "tinyIncrements",
        "tinyInteger",
        "tinyText",
        "unsignedBigInteger",
        "unsignedDecimal",
        "unsignedInteger",
        "unsignedMediumInteger",
        "unsignedSmallInteger",
        "unsignedTinyInteger",
        "uuid",
        "uuidMorphs",
        "year",
        "addColumn",
    }
)


def _clean_string(raw: str) -> str:
    return raw.strip("'\"")


def _get_string_arg(args_node: Node | None, source: bytes, index: int = 0) -> str | None:
    if args_node is None:
        return None
    real_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
    if index < len(real_args):
        text = node_text(real_args[index], source).strip()
        if text.startswith(("'\"", "'", '"')) or (text and not text.startswith("$")):
            return _clean_string(text)
    return None


def _extract_columns_from_call(
    method_name: str, args_node: Node | None, source: bytes
) -> list[str]:
    if method_name in ("timestamps", "timestampsTz", "nullableTimestamps"):
        return ["created_at", "updated_at"]
    if method_name == "rememberToken":
        return ["remember_token"]
    if method_name in ("softDeletes", "softDeletesTz"):
        col = _get_string_arg(args_node, source, 0)
        return [col if col else "deleted_at"]
    if method_name in ("morphs", "nullableMorphs", "uuidMorphs", "nullableUuidMorphs"):
        prefix = _get_string_arg(args_node, source, 0)
        if prefix:
            return [f"{prefix}_type", f"{prefix}_id"]
        return []
    if method_name == "id":
        col = _get_string_arg(args_node, source, 0)
        return [col if col else "id"]
    if method_name == "addColumn":
        col = _get_string_arg(args_node, source, 1)
        return [col] if col else []

    col = _get_string_arg(args_node, source, 0)
    return [col] if col else []


def _extract_file_schema(
    scoped_calls: list[Node], parsed: ParsedFile, schema: dict[str, set[str]]
) -> None:
    source = parsed.source

    for call_node in scoped_calls:
        scope = call_node.child_by_field_name("scope")
        name = call_node.child_by_field_name("name")
        if scope is None or name is None:
            continue

        scope_text = node_text(scope, source)
        name_text = node_text(name, source)
        if scope_text != "Schema" or name_text not in ("create", "table"):
            continue

        args_node = call_node.child_by_field_name("arguments")
        if args_node is None:
            continue

        table_name = _get_string_arg(args_node, source, 0)
        if not table_name:
            continue

        for member_call in find_all(call_node, "member_call_expression"):
            m_name_node = member_call.child_by_field_name("name")
            if m_name_node is None:
                continue
            m_name = node_text(m_name_node, source)
            if m_name in _COLUMN_METHODS:
                m_args = member_call.child_by_field_name("arguments")
                cols = _extract_columns_from_call(m_name, m_args, source)
                for c in cols:
                    if c:
                        schema[table_name].add(c)


def extract_schema(
    scoped_calls_by_file: dict[Path, list[Node]],
    files: dict[Path, ParsedFile],
) -> dict[str, set[str]]:
    """Extract database table column schemas from migration files."""
    schema: dict[str, set[str]] = defaultdict(set)
    for path, parsed in files.items():
        if b"Schema::" not in parsed.source:
            continue
        _extract_file_schema(scoped_calls_by_file.get(path, []), parsed, schema)
    return {k: set(v) for k, v in schema.items()}
