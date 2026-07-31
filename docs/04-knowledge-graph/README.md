# Knowledge Graph

The knowledge graph is the product. Findings, explanations, attack paths, reports and MCP
answers are all queries over it. Everything else is plumbing around this data structure.

## Layers

One property graph, several edge families. Layers share a node namespace so a query can hop
between them - that is the whole point of unifying them.

| Layer | Nodes | Edges | Built by |
| --- | --- | --- | --- |
| **AST** | file, class, method, statement, expression | `CHILD_OF`, `NEXT_SIBLING` | [03-parser](../03-parser/README.md) |
| **Symbol** | class, method, property, function, constant | `EXTENDS`, `IMPLEMENTS`, `USES_TRAIT`, `DECLARES`, `IMPORTS` | parser |
| **Call** | method, function, closure | `CALLS`, `INSTANTIATES`, `RESOLVES_TO` | [07-call-graph](../07-call-graph/README.md) |
| **Control flow** | basic block | `FLOWS_TO`, `BRANCH_TRUE`, `BRANCH_FALSE`, `THROWS`, `CATCHES` | graph engine |
| **Data flow** | variable, parameter, return, property | `ASSIGNS_TO`, `PROPAGATES_TO`, `TAINTS`, `SANITIZES` | [05-data-flow](../05-data-flow-analysis/README.md) |
| **Framework** | route, controller action, middleware, model, policy, template, job, command | `HANDLES`, `PROTECTED_BY`, `RENDERS`, `AUTHORIZES`, `BINDS`, `DISPATCHES` | [08-adapters](../08-framework-adapters/README.md) |
| **Dependency** | package, version, advisory | `DEPENDS_ON`, `AFFECTED_BY`, `RESOLVES_TO_VERSION` | dependency scanner |
| **Infrastructure** | container, service, host, port *(v2.0)* | `EXPOSES`, `RUNS`, `CONNECTS_TO` | infra plugin |

## Node model

```text
Node
  id            stable, deterministic: sha1(project_id : kind : fqn : discriminator)
  kind          route | class | method | variable | package | …
  name, fqn
  file_id, start_byte, end_byte, start_line, start_col, end_line, end_col
  attrs         JSON, kind-specific
```

```text
Edge
  id, src_id, dst_id
  kind          CALLS | PROPAGATES_TO | PROTECTED_BY | …
  attrs         JSON - e.g. {"resolution": "facade", "confidence": 0.9, "arg_index": 2}
  provenance    which analysis produced it
```

**Node IDs must be deterministic and content-derived.** It is what makes findings stable across
runs (so they can be baselined and suppressed), incremental invalidation possible, and reports
diffable. Any scheme using autoincrement IDs or iteration order breaks all three.

**The span is deliberately not in the ID.** An earlier version of this document specified
`sha1(project_id : kind : fqn : span)`, which contradicts the stability requirement above:
inserting one comment moves the span of every node below it, so a reformat with no code change
would change IDs and un-suppress findings across the file. `discriminator` replaces it, and is
what distinguishes nodes the symbol table does not name uniquely - the third `$name` in a
method, a closure, a basic block. Callers derive it from an ordinal position within the parent,
never from a line number, a byte offset or iteration order, all of which reintroduce the same
instability. It is empty for anything with a unique FQN. The span still lives on the node as
`start_byte`/`end_byte` and friends, where moving it is correct; it just cannot be identity.

`confidence` on an edge is not decoration. A `CALLS` edge resolved through a facade map is
near-certain; one resolved through `call_user_func($handler)` is a guess. Taint paths carry the
minimum confidence of their edges, and that value drives severity and reporting thresholds.

## Why one graph and not several tools

The queries that make Vigilloo different are cross-layer. Each of these is one traversal:

```text
"Which routes reach an unparameterised SQL sink?"
  route --HANDLES--> action --CALLS*--> method --TAINTS--> sink[kind=sql, sanitized=false]

"Which of those are reachable without authentication?"
  … and NOT (route --PROTECTED_BY--> middleware[name in ('auth','auth:sanctum')])

"Which mass-assignment sinks touch a privileged column?"
  action --CALLS--> Model::create --BINDS--> model[guarded=[]] --DECLARES--> property[name~'admin|role']

"Which vulnerable package versions are actually called from our code?"
  package --AFFECTED_BY--> advisory
  AND package --DECLARES--> method <--CALLS*-- action <--HANDLES-- route
```

That last one is the difference between "you have 47 vulnerable dependencies" and "3 of your
47 vulnerable dependencies are reachable from a public route".

## Storage

**SQLite** for v0.1 - `nodes` and `edges` tables with indexes on `(kind)`, `(file_id)`,
`(src_id, kind)`, `(dst_id, kind)`. Recursive CTEs handle transitive traversal, which is enough
for reachability and path-finding at target scale. Schema in [17-database](../17-database/README.md).

**NetworkX** in memory for algorithms that are painful in SQL: dominators, SCC condensation for
recursive call cycles, k-shortest-paths for attack path ranking. Loaded per layer on demand, not
wholesale. At 1M LOC the full AST layer does not fit comfortably in memory, so AST-level queries
stay in SQL and only the call/data-flow layers get materialised.

**Neo4j** stays a future option for the cloud tier, behind the same store interface. Not a v0.1
dependency, and nothing in core may assume Cypher.

## Export

`vigilloo graph export --format {json,graphml,dot,gexf} [--layer …] [--focus <node>] [--depth N]`

- **JSON** - the canonical, lossless form; what MCP and the desktop app consume.
- **GraphML / GEXF** - Gephi, yEd, Cytoscape.
- **DOT** - Graphviz, and small focused subgraphs pasted into reports.

Whole-graph export at scale is unusable as a picture, so `--focus` + `--depth` (ego network
around a node) is the primary interactive mode. Report diagrams show the taint path only.

**What is built today: the JSON and GraphML serialisers only, in `vigilloo.graph_export`, as
two functions over a project's nodes and edges.** DOT, GEXF, `--layer`, `--focus`, `--depth`
and the `vigilloo graph` command itself are still specified only - the CLI surface is its own
task, and the whole-graph filters above are what makes it worth designing once rather than
growing an option at a time. Both serialisers accept either the rows a scan has just built or
the rows read back out of SQLite by `store.graph_for_project`, so exporting a project scanned
earlier never means re-analysing it.

The persisted symbol/call layer also includes trait nodes and `USES_TRAIT` edges. Calls to
inherited or trait-provided methods point at the method node that actually declares the body,
and a route whose action is inherited uses that same real node for `HANDLES`. No edge points at
a synthetic `Child::method` node that does not exist.

Both formats are byte-identical across two exports of the same graph (invariant 8), which
means neither may inherit the order it was handed: nodes sort by kind, then fqn, then id, and
edges by kind, endpoints, confidence, resolution and attributes - an edge has no id to break
the tie with. JSON objects are the node and edge fields under their own names, with absent
optional fields omitted rather than written as `null`, so a consumer reconstructs a row by
splatting the object. GraphML declares a `<key>` for each of those fields ahead of the
`<graph>`; the kind-specific `attrs` bag travels as one JSON-typed string, because GraphML has
no list type and a key set derived from whichever attribute names a project happens to produce
would change under the user between two scans of the same codebase.

## Invalidation

A file's content hash changes → its AST/symbol nodes are dropped and rebuilt → every edge
touching them is dropped → callers are invalidated transitively through the call graph →
affected taint paths are recomputed. Framework facts rebuild when routes, models, middleware,
policies or config change. Correctness here is what makes NFR-2 (5-second incremental scans)
achievable without lying about results.
