"""Tree-sitter based PHP parsing.

Knows nothing about Laravel or about security. Framework meaning is added in
vigilloo.laravel, security meaning in vigilloo.rules.
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Node, Parser, Tree

from .models import ParseFailure, Span, Suppression


@dataclass
class FileRecord:
    """Nodes collected during a single pass over a file's AST."""

    namespaces: list[Node]
    imports: list[Node]
    classes: list[Node]
    traits: list[Node]
    member_calls: list[Node]
    scoped_calls: list[Node]
    properties: list[Node]
    comments: list[Node]


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


def collect_nodes(root: Node) -> FileRecord:
    """Single pass over the AST to collect constructs for all downstream extractors."""
    record = FileRecord([], [], [], [], [], [], [], [])
    for node in walk(root):
        t = node.type
        if t == "namespace_definition":
            record.namespaces.append(node)
        elif t == "namespace_use_declaration":
            record.imports.append(node)
        elif t in ("class_declaration", "enum_declaration"):
            record.classes.append(node)
        elif t == "trait_declaration":
            record.traits.append(node)
        elif t == "member_call_expression":
            record.member_calls.append(node)
        elif t == "scoped_call_expression":
            record.scoped_calls.append(node)
        elif t == "property_element":
            record.properties.append(node)
        elif t == "comment":
            record.comments.append(node)
    return record


def find_all(node: Node, type_name: str) -> list[Node]:
    return [n for n in walk(node) if n.type == type_name]


def find_any(node: Node, type_names: tuple[str, ...]) -> list[Node]:
    """Every descendant of one of several types, in document order.

    One walk rather than one per type, and the difference is not performance.
    Concatenating two `find_all` results groups the matches by type, so a
    statement holding `$a->x($tainted)` and `$b?->y($tainted)` would be visited
    in an order that depends on which type was listed first rather than on where
    the calls appear. The walk emits path steps as it goes, and invariant 8
    requires the same input to produce byte-identical output.
    """
    wanted = frozenset(type_names)
    return [n for n in walk(node) if n.type in wanted]


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


def extract_suppressions(comments: list[Node], parsed: ParsedFile) -> list[Suppression]:
    """Extract inline suppressions from a pre-collected list of comments.

    Matches `// vigilloo-ignore rule-id -- justification`.
    If the justification or rule ID is missing, `is_invalid` is True.
    """
    suppressions = []

    # regex matches:
    # 1. optional whitespace
    # 2. rule id (optional group 1)
    # 3. optional whitespace + '--' + optional whitespace + justification (optional group 2)
    # The prefix `// vigilloo-ignore` or `/* vigilloo-ignore` is handled via a broader match first.
    ignore_pattern = re.compile(r"vigilloo-ignore\s*([a-z0-9.-]+)?(?:\s*--\s*(.+))?")

    for node in comments:
        text = node_text(node, parsed.source).strip()

        # Strip //, /*, #, */
        if text.startswith("//") or text.startswith("/*") or text.startswith("#"):
            text = text.lstrip("/*# \t").rstrip("*/ \t")

        if "vigilloo-ignore" in text:
            match = ignore_pattern.search(text)
            if not match:
                continue

            rule_id = match.group(1)
            justification = match.group(2)

            is_invalid = False
            if not rule_id or not justification or not justification.strip():
                is_invalid = True

            # Node start row is 0-indexed, so start_point[0] + 1 is the 1-indexed line number.
            line = node.start_point[0] + 1

            suppressions.append(
                Suppression(
                    file=parsed.path,
                    line=line,
                    rule_id=rule_id or "",
                    justification=(justification or "").strip(),
                    is_invalid=is_invalid,
                )
            )

    return suppressions
