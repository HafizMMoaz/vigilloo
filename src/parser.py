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

from .models import Span


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


def parse_source(path: Path, source: bytes) -> ParsedFile:
    """Parse text that is already in hand, attributed to `path`.

    Separate from parse_php so a caller holding derived text - Blade rewritten
    into PHP - can have it parsed while spans still point at the original file.
    The parser stays unaware of what produced the text.
    """
    tree = _parser().parse(source)
    return ParsedFile(
        path=path,
        source=source,
        tree=tree,
        has_errors=tree.root_node.has_error,
    )


def parse_php(path: Path) -> ParsedFile:
    """Parse one PHP file. Never raises for malformed input."""
    return parse_source(path, path.read_bytes())


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


def find_all(node: Node, type_name: str) -> list[Node]:
    return [n for n in walk(node) if n.type == type_name]
