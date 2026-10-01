"""Symbol table construction: namespaces, imports, classes, methods, properties.

Compatibility re-export for vigilloo.parser.symbols.
"""

from .parser.symbols import (
    PARSER_VERSION,
    ClassInfo,
    FileSymbols,
    extract_symbols,
    resolve_type_name,
)

__all__ = [
    "PARSER_VERSION",
    "ClassInfo",
    "FileSymbols",
    "extract_symbols",
    "resolve_type_name",
]
