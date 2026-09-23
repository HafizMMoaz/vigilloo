"""Content-derived node identity.

Invariant 3 in CLAUDE.md: node ids are content-derived and deterministic, never
autoincrement. Stable ids are what make baselines, suppressions and incremental
invalidation work, and all three break together when they are not.

The scheme is specified in docs/04-knowledge-graph section "Node model", corrected in
docs/plans/2026-07-28-slice-8-graph-ids-design.md: the span the doc originally named is
not in the hash. See `node_id`.

Deliberately knows nothing about PHP, Laravel, tree-sitter or the store. It takes four
strings and returns one, so the graph layer and every adapter above it can derive the same
id for the same node without any of them owning the rule.
"""

import hashlib

# 16 hex characters, 64 bits, matching Finding.id and Finding.fingerprint. Over the ~10M
# nodes docs/17-database section "Scale" expects from 1M LOC that is a collision probability
# near 3e-6, and this string is repeated in both endpoints of every edge row.
_ID_LENGTH = 16

_SEPARATOR = "|"


def node_id(project_id: int, kind: str, fqn: str, *, discriminator: str = "") -> str:
    """The stable id of one graph node.

    `sha1(project_id | kind | fqn | discriminator)`, truncated. What is *not* in it is the
    point: docs/04-knowledge-graph originally specified the node's span, and a span cannot
    satisfy the stability that same section requires. Inserting one comment above a class
    moves the span of that class and of everything below it, so a span-derived id would
    change for a file whose code did not change - un-suppressing findings and invalidating
    caches on a reformat, which is the exact failure `Finding.fingerprint` exists to avoid
    one layer up. docs/22-testing section "Property-based testing" states the requirement as
    a test, and tests/test_ids.py is that test.

    - `project_id` namespaces one project's nodes from another's in a shared database.
    - `kind` separates a file node from the class node that happens to share its name.
    - `fqn` is the content. Renaming a symbol changes its id, which is correct: it is a
      different symbol, and pretending otherwise would carry a finding across a rename.
    - `discriminator` is what replaces the span for nodes the symbol table does not name
      uniquely: the third `$name` in a method, a closure, a basic block. Callers derive it
      from position *within its parent* - an ordinal - and never from a line number, a byte
      offset or iteration order, all of which reintroduce the instability above. Empty for
      anything with a unique fqn.

    None of the four parts may contain `|`. PHP names cannot, the kind vocabulary in
    docs/04-knowledge-graph does not, and a discriminator is built from ordinals and names,
    so this costs nothing to honour and keeps the joined string unambiguous.
    """
    parts = [str(project_id), kind, fqn, discriminator]
    return hashlib.sha1(_SEPARATOR.join(parts).encode()).hexdigest()[:_ID_LENGTH]
