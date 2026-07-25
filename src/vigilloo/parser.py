"""Tree-sitter based PHP parsing.

Knows nothing about Laravel or about security. Framework meaning is added in
vigilloo.laravel, security meaning in vigilloo.rules.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Node, Parser, Tree

from vigilloo.models import Span


@cache
def _parser() -> Parser:
    # The text-mode `php` grammar handles `?>` ... `<?php` interleaving.
    return Parser(Language(tree_sitter_php.language_php()))


@dataclass(frozen=True)
class ParsedFile:
    path: Path
    source: bytes
    tree: Tree
    has_errors: bool


def parse_php(path: Path) -> ParsedFile:
    """Parse one PHP file. Never raises for malformed input."""
    source = path.read_bytes()
    tree = _parser().parse(source)
    return ParsedFile(
        path=path,
        source=source,
        tree=tree,
        has_errors=tree.root_node.has_error,
    )


def node_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def node_span(node: Node, path: Path) -> Span:
    start_row, start_col = node.start_point
    end_row, end_col = node.end_point
    return Span(path, start_row + 1, start_col, end_row + 1, end_col)


def walk(node: Node) -> Iterator[Node]:
    """Depth-first walk over every descendant, including node itself."""
    yield node
    for child in node.children:
        yield from walk(child)


def children_of_type(node: Node, type_name: str) -> list[Node]:
    return [c for c in node.children if c.type == type_name]


def find_all(node: Node, type_name: str) -> list[Node]:
    return [n for n in walk(node) if n.type == type_name]
