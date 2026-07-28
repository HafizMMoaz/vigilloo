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

from .models import ParseFailure, Span


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


# The declarations worth naming in a parse failure, and the word each is called
# by in a report. A construct earns a place here by being something a developer
# can go and open: "the method OrderController::search failed to parse" is a
# task, "an ERROR node at byte 4172" is a puzzle. Anonymous forms - closures,
# arrow functions, anonymous classes - are deliberately absent, because naming
# one would mean inventing a name, and a made-up location is worse than the
# honest fallback to the file (see _enclosing_construct).
_NAMED_CONSTRUCTS = {
    "method_declaration": "method",
    "function_definition": "function",
    "class_declaration": "class",
    "interface_declaration": "interface",
    "trait_declaration": "trait",
    "enum_declaration": "enum",
}

# The declarations a method can hang off, used only to qualify its name.
_TYPE_DECLARATIONS = (
    "class_declaration",
    "interface_declaration",
    "trait_declaration",
    "enum_declaration",
)


def _error_nodes(node: Node) -> Iterator[Node]:
    """Every error node under `node`, without descending where there are none.

    tree-sitter marks a syntax error either with an `ERROR` node or by inserting
    a `MISSING` one, and sets `has_error` on every ancestor of both. That flag is
    what makes this affordable: the whole point of walking from the root is to
    find a handful of errors in a tree with thousands of nodes, and pruning at
    every child whose subtree is clean turns a full traversal into a walk down
    the few branches that actually broke. `walk`/`find_all` would visit all of
    them and materialise a list besides.

    An error inside an error is not descended into. It resolves to the same
    enclosing construct as its parent does, so it would only produce a duplicate.
    """
    for child in node.children:
        if child.type == "ERROR" or child.is_missing:
            yield child
        elif child.has_error:
            yield from _error_nodes(child)


def _enclosing_construct(node: Node, source: bytes) -> tuple[str, str]:
    """The (kind, name) of the smallest named construct containing `node`.

    Climbs to the first ancestor that is both a construct worth naming and
    actually named. An unnamed one is climbed past rather than reported: a
    malformed declaration can lose its own name node, and a closure never had
    one, so `("class", "")` would be a report that points nowhere. A method is
    qualified with its class - `OrderController::search` - because a bare
    `search` is not a place either.

    Returns `("file", "")` when the error belongs to no named construct at all,
    which is the honest answer for a stray token at the top level and the reason
    this returns a fallback rather than None.
    """
    current = node.parent
    while current is not None:
        kind = _NAMED_CONSTRUCTS.get(current.type)
        if kind is not None:
            name = node_text(current.child_by_field_name("name"), source)
            if name:
                if kind == "method":
                    owner = current.parent
                    while owner is not None and owner.type not in _TYPE_DECLARATIONS:
                        owner = owner.parent
                    if owner is not None:
                        owner_name = node_text(owner.child_by_field_name("name"), source)
                        if owner_name:
                            name = f"{owner_name}::{name}"
                return kind, name
        current = current.parent
    return "file", ""


def error_constructs(parsed: ParsedFile) -> tuple[ParseFailure, ...]:
    """Which constructs in `parsed` failed to parse, deduplicated and sorted.

    Invariant 4 says coverage is reported and never hidden, and a file path is
    only half of that report: it says a scan went blind somewhere in three
    hundred lines without saying where, so the parse-rate gate points at a
    filename instead of at a cause. This names the construct instead.

    Returns empty for a clean file before touching the tree. Every scan of every
    healthy project takes that path, and it must cost one boolean read.

    Sorted, not walk-ordered, because it feeds a report and invariant 8 requires
    the same input to render byte-identically. Deduplicated because one broken
    method usually produces several error nodes - an unclosed parameter list and
    the unterminated call after it - and reporting one construct twice tells the
    reader nothing the first mention did not.
    """
    if not parsed.has_errors:
        return ()

    failures = {
        ParseFailure(parsed.path, *_enclosing_construct(node, parsed.source))
        for node in _error_nodes(parsed.tree.root_node)
    }
    return tuple(sorted(failures))
