"""Tree-sitter PHP parser integration and symbol extraction."""

from .engine import (
    FileRecord,
    ParsedFile,
    _enclosing_construct,
    _error_nodes,
    _parser,
    collect_nodes,
    error_constructs,
    extract_suppressions,
    find_all,
    find_any,
    node_span,
    node_text,
    parse_php,
    parse_source,
    walk,
)
from .symbols import (
    PARSER_VERSION,
    ClassInfo,
    FileSymbols,
    extract_symbols,
    resolve_type_name,
)

__all__ = [
    "PARSER_VERSION",
    "ClassInfo",
    "FileRecord",
    "FileSymbols",
    "ParsedFile",
    "_enclosing_construct",
    "_error_nodes",
    "_parser",
    "collect_nodes",
    "error_constructs",
    "extract_suppressions",
    "extract_symbols",
    "find_all",
    "find_any",
    "node_span",
    "node_text",
    "parse_php",
    "parse_source",
    "resolve_type_name",
    "walk",
]
