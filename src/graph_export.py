"""Graph export for external tooling: the JSON and GraphML forms of docs/04-knowledge-graph.

Named `graph_export.py` and not `graph/export.py`, which is what the backlog entry for
TASK-014 asks for, because `src/graph.py` already exists as a flat module and a directory of
the same name cannot sit beside it. Consolidating the flat modules into the subpackages
docs/23-dev-guide specifies is its own task (TASK-116); doing it one module at a time strands
the repo half-migrated, with `graph.py` and `graph/` meaning different things to a reader. The
same decision was already taken for `src/ids.py`. Do not "fix" this in isolation.

Both exporters take the nodes and edges themselves rather than a `GraphRows`, so one function
serves both callers there are: a scan that has just built the graph in memory, and
`vigilloo.store.graph_for_project`, which reads it back out of SQLite without re-scanning.
Reading from the store is the more useful of the two - a `vigilloo graph export` command must
not have to re-analyse a project to print what it already stored - and it is only available
because the seam is the row types and not the builder's return value. `GraphRows` additionally
carries `unresolved_calls`, which the store does not persist, so a reader returning one would
have to invent a zero for it and claim a gap it never measured.

Every ordering here is imposed by this module, never inherited. `graph_rows` emits in a
deterministic order but a grouped one, and rows read back from SQLite arrive in whatever order
the query planner chose; invariant 8 makes byte-identical output the contract for both.
"""

import json

# Stdlib ElementTree, used to *write* only. Nothing here parses XML, so the XXE and
# billion-laughs surface that would make `defusedxml` the right answer does not exist - and a
# module that only serialises is not worth a runtime dependency against invariant 6. If a
# GraphML *importer* ever lands, it is reading a file some other tool produced, and that is the
# point at which hardened parsing becomes a requirement rather than a reflex.
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from dataclasses import fields

from .models import EdgeRow, NodeRow

# Bumped when the shape of the JSON changes, never when the graph's contents do. A consumer
# that has to guess which of two incompatible shapes it is holding is a consumer that breaks
# silently on upgrade.
JSON_FORMAT_VERSION = 1

_GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"
_XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
_GRAPHML_XSD = "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"

# Every attribute either exporter emits, and the GraphML type it declares. GraphML has no list
# and no nested-object type, so `attrs` - the kind-specific bag from docs/04-knowledge-graph,
# which holds a route's verbs and a method's parameter names - travels as its JSON text.
#
# ponytail: one opaque `attrs` column rather than one GraphML key per attribute name. Ceiling:
# Gephi and yEd show `attrs` as a single unfilterable string, so "colour every route whose
# unresolved_middleware is non-zero" is not a click. Acceptable because the attributes that
# drive layout and filtering - kind, name, fqn - are already top-level columns, and because a
# key set derived from whichever attribute names a given project happens to produce is a
# schema that changes under the user between two scans of the same codebase. Upgrade trigger:
# a second consumer of the GraphML that filters on a kind-specific attribute, at which point
# the key set comes from the vocabulary in docs/04-knowledge-graph rather than from the data.
_NODE_KEYS: tuple[tuple[str, str], ...] = (
    ("kind", "string"),
    ("name", "string"),
    ("fqn", "string"),
    ("file_id", "int"),
    ("start_line", "int"),
    ("start_col", "int"),
    ("end_line", "int"),
    ("end_col", "int"),
    ("start_byte", "int"),
    ("end_byte", "int"),
    ("attrs", "string"),
)

_EDGE_KEYS: tuple[tuple[str, str], ...] = (
    ("kind", "string"),
    ("confidence", "double"),
    ("resolution", "string"),
    ("attrs", "string"),
)


def export_json(nodes: Iterable[NodeRow], edges: Iterable[EdgeRow]) -> str:
    """The canonical, lossless form: what MCP and the desktop app consume.

    Each node and edge is its row's fields under their own names, so a consumer can rebuild a
    `NodeRow` or an `EdgeRow` by splatting the object straight into the constructor. Keys whose
    value is `None` are left out rather than written as `null` - every one of them is optional
    on the dataclass, so absence and null already mean the same thing, and the file is
    materially smaller for a graph that is mostly nodes with no span.

    Sorted, and `sort_keys` on the way out. Invariant 8 is byte-identical output for the same
    input, and both a dict's insertion order and a SQL result's row order are accidents of how
    the rows were produced rather than anything a caller promised.
    """
    payload = {
        "format": "vigilloo.graph",
        "version": JSON_FORMAT_VERSION,
        "nodes": [_row_dict(node) for node in sorted(nodes, key=_node_key)],
        "edges": [_row_dict(edge) for edge in sorted(edges, key=_edge_key)],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def export_graphml(nodes: Iterable[NodeRow], edges: Iterable[EdgeRow]) -> str:
    """GraphML 1.0, for Gephi, yEd and Cytoscape.

    Structure is the schema's: every `<key>` declared before the `<graph>` that uses it, then
    all nodes, then all edges. The declarations are the fixed set in `_NODE_KEYS`/`_EDGE_KEYS`
    and not whatever the data happened to contain, so a `<data>` element referencing an
    undeclared key cannot be emitted.

    An `<edge>` carries no `id`. GraphML makes it optional and an edge here has no identity of
    its own - it is (src, dst, kind) between two nodes that do have one, which is the same
    reason `store.insert_edges` lets SQLite assign the rowid. Inventing an ordinal would create
    a name that changes whenever an unrelated edge is added above it.
    """
    root = ET.Element(
        "graphml",
        {
            # Written as plain attributes rather than through ET.register_namespace, which
            # mutates a process-global prefix table. Nothing here is parsed back with
            # namespace-aware lookups, so the registry buys nothing and costs action at a
            # distance for any other XML this process touches.
            "xmlns": _GRAPHML_NS,
            "xmlns:xsi": _XSI_NS,
            "xsi:schemaLocation": f"{_GRAPHML_NS} {_GRAPHML_XSD}",
        },
    )
    for name, attr_type in _NODE_KEYS:
        _declare_key(root, "node", name, attr_type)
    for name, attr_type in _EDGE_KEYS:
        _declare_key(root, "edge", name, attr_type)

    # Directed, because every edge kind in docs/04-knowledge-graph is: a caller CALLS a callee
    # and the reverse is a different fact. An undirected export would let a traversal in Gephi
    # walk a call backwards and read it as reachability.
    graph = ET.SubElement(root, "graph", {"id": "G", "edgedefault": "directed"})

    for node in sorted(nodes, key=_node_key):
        element = ET.SubElement(graph, "node", {"id": node.id})
        _write_data(element, "n", _NODE_KEYS, node)
    for edge in sorted(edges, key=_edge_key):
        element = ET.SubElement(graph, "edge", {"source": edge.src_id, "target": edge.dst_id})
        _write_data(element, "e", _EDGE_KEYS, edge)

    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{body}\n'


def _declare_key(root: ET.Element, target: str, name: str, attr_type: str) -> None:
    """One `<key>` declaration. Ids are prefixed because they share one namespace.

    `kind` and `attrs` exist on both a node and an edge, and GraphML requires every key id in
    the document to be distinct, so a bare `id="kind"` would be the same declaration twice.
    """
    ET.SubElement(
        root,
        "key",
        {
            "id": f"{target[0]}_{name}",
            "for": target,
            "attr.name": name,
            "attr.type": attr_type,
        },
    )


def _write_data(
    element: ET.Element,
    prefix: str,
    keys: tuple[tuple[str, str], ...],
    row: NodeRow | EdgeRow,
) -> None:
    """A `<data>` child per attribute the row actually has, in declaration order.

    `None` is written as no element at all rather than as an empty one: GraphML has no null,
    and `<data key="n_fqn"></data>` says the node's fqn is the empty string, which is a
    different claim from not having one.
    """
    for name, _ in keys:
        value = getattr(row, name)
        if value is None:
            continue
        data = ET.SubElement(element, "data", {"key": f"{prefix}_{name}"})
        data.text = _attrs_text(value) if name == "attrs" else str(value)


def _row_dict(row: NodeRow | EdgeRow) -> dict[str, object]:
    """The row's own fields, minus the ones that are None. See `export_json`."""
    out: dict[str, object] = {}
    for field in fields(row):
        value = getattr(row, field.name)
        if value is None:
            continue
        out[field.name] = dict(value) if field.name == "attrs" else value
    return out


def _attrs_text(attrs: Mapping[str, object]) -> str:
    """The attribute bag as JSON, keys sorted, matching `store._attrs_json`.

    Deliberately the same serialisation the store writes into the `attrs` column, so a graph
    exported from memory and the same graph exported after a round trip through SQLite are the
    same bytes rather than two spellings of one mapping.
    """
    return json.dumps(attrs, sort_keys=True)


def _node_key(node: NodeRow) -> tuple[str, str, str]:
    """Group by kind, then by name within a kind, and break every tie on the id.

    The id is content-derived and unique, so ending on it makes the order total: two nodes can
    share a kind and an fqn only by being the same node. Leading with kind and fqn rather than
    with the id alone is for the reader, since a sha1 prefix sorts into no useful order.
    """
    return (node.kind, node.fqn or "", node.id)


def _edge_key(edge: EdgeRow) -> tuple[str, str, str, float, str, str]:
    """Total over everything an edge is, because an edge has no id to fall back on.

    Two edges identical in every field are genuinely the same edge stored twice, and sorting
    on every field puts them adjacent and in a fixed order instead of leaving their relative
    position to the sort's input.
    """
    return (
        edge.kind,
        edge.src_id,
        edge.dst_id,
        edge.confidence,
        edge.resolution or "",
        _attrs_text(edge.attrs or {}),
    )
