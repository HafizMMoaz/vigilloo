# Slice 8 Design: Graph Tables and Node Identity

**Status:** designing.
**Builds on** slice 6, which created `.vigilloo/vigilloo.db` and deliberately left `nodes` and
`edges` out (docs/plans/2026-07-27-slice-6-store-design.md, "Not implemented"). Backlog
TASK-008 and TASK-009.

## Why this slice

The graph is the product, and it lives entirely in memory. Persisting it is what makes
incremental scanning, `graph export` and cross-scan queries possible, and none of them can be
built against a schema that does not exist. This slice lands the storage and the identity
scheme those readers need, in that order: the tables and their batch write path, then the
content-derived node id that every row in them is keyed on.

Nothing writes graph rows yet. Turning `Project` into nodes and edges is TASK-010, and doing
it in the same slice would mix a storage decision with a modelling one.

## Scope

| Task | Lands |
| --- | --- |
| TASK-008 | `nodes`, `edges` and the five indexes from [17-database](../17-database/README.md), inside the one versioned DDL constant in `src/store.py`. `insert_nodes` / `insert_edges`, one `executemany` per batch. |
| TASK-009 | `src/ids.py`: `node_id`, the content-derived node identity of invariant 3. |

Non-goals, and why:

- **Writing the graph.** TASK-010. This slice is the schema and the identity, not the mapping.
- **Reading the graph back.** No traversal, no recursive CTE, no export. There is nothing
  stored to traverse.
- **`src/graph/` as a package.** `graph.py` stays flat until TASK-116 moves every flat module
  together. The id derivation therefore lands as `src/ids.py`, a module, which needs no
  `pyproject.toml` entry.
- **A content-derived `edges.id`.** [17-database](../17-database/README.md) declares an
  autoincrement rowid, because an edge's identity is (src, dst, kind) between two nodes that
  already have one. Recorded as a `ponytail:` at `insert_edges`, with `UNIQUE (src_id, dst_id,
  kind)` as the upgrade when incremental scanning starts re-deriving one file at a time.

## Spec correction: node ids cannot contain the span

[04-knowledge-graph](../04-knowledge-graph/README.md) section "Node model" specifies

```text
id  stable, deterministic: sha1(project_id : kind : fqn : span)
```

and three lines later requires those ids to be stable across runs so that findings can be
baselined and incremental invalidation can work. [22-testing](../22-testing/README.md) section
"Property-based testing" states the same requirement as a test: *node IDs are stable under
whitespace and comment changes*. A span cannot satisfy that. Inserting one comment above a
class moves the span of that class and of everything below it, so a span-derived id changes
for a file whose code did not change - which is exactly the reformat-resurrects-the-backlog
failure that `Finding.fingerprint` exists to avoid, one layer lower.

Resolved, with both docs updated in the same commit as the code:

```text
node_id = sha1("project_id|kind|fqn|discriminator")[:16]
```

- **`project_id`** namespaces one project's nodes from another's in a shared database, as the
  doc already had it.
- **`kind`** separates the class node from the file node when a single-class file names both
  the same thing.
- **`fqn`** is the content. Renaming a symbol changes its id, which is correct: it is a
  different symbol.
- **`discriminator`** replaces the span for nodes that have no unique fqn - the third `$name`
  in a method, a closure, a basic block. It is caller-supplied and must be derived from
  position *within its parent* (an ordinal), never from a line, a byte offset or iteration
  order. Empty for anything the symbol table already names uniquely.

Truncated to 16 hex characters, matching `Finding.id` and `Finding.fingerprint`: 64 bits over
the ~10M nodes a 1M LOC project produces ([17-database](../17-database/README.md), "Scale")
leaves a collision probability around 3e-6, and the column is repeated in every edge row.

## Supporting change: the schema version is enforced

`nodes` and `edges` change the schema, so `_SCHEMA_VERSION` becomes 2. The store creates the
schema whole and has no migration runner, so a database written by any other version is now
refused with an error naming the file to delete, instead of being opened and failing later
with "no such table: nodes". The `ponytail:` at that check names the forward-only runner from
[17-database](../17-database/README.md) section "Migrations" as the upgrade, and its trigger:
the first released version, after which deleting a user's findings history is not an option.

`evidence_paths.node_id` gains the `REFERENCES nodes(id)` it was always specified to have.
Slice 6 left it off because SQLite could not check a foreign key into a table that did not
exist; the table exists now, and that divergence note is deleted rather than moved.

## Tests

`tests/test_store.py`:

| Test | Guards |
| --- | --- |
| The graph tables and their five indexes exist | docs/17-database, column for column. Without the indexes every traversal is a table scan. |
| 10k nodes go in as one batch | The acceptance case for docs/23-dev-guide section Performance: no N+1 insert. |
| A batch that violates a constraint writes none of it | One transaction for the batch, not one per row. |
| Re-inserting a content-derived id is a no-op | Invariant 3: the same node re-derived is the same node. |
| Nodes and edges round-trip with their attributes | Including sorted `attrs` JSON, for invariant 8. |
| An edge to an unknown node is rejected | The graph must not hold a dangling edge. |
| A database from another schema version is refused loudly | The version check above. |

`tests/test_ids.py`:

| Test | Guards |
| --- | --- |
| Whitespace and comment insertion never change a node id (Hypothesis) | The property docs/22-testing names. End to end through the parser and the symbol table, so it fails if anyone puts the span back. |
| Renaming a class changes every id under it | The other half: stable is not the same as constant. |
| Kind, project and discriminator each change the id | No two distinct nodes share an id. |
| A known input hashes to a known value | The scheme itself is part of the contract; ids ship in stored graphs. |

Hypothesis joins the dev group for the first of these, pinned to one minor like the rest of
the toolchain. docs/22-testing already names it as the tool for this property.
