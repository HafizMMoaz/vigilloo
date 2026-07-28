"""Graph export: the JSON and GraphML forms, their determinism, and the store round trip.

Everything runs over the real fixture rather than a hand-built graph. A three-node graph
assembled here would exercise none of what makes export hard - a route's list-valued attrs, a
node with no span, an edge with a resolution and one without - and would keep passing after
the graph builder started producing something the exporter cannot represent.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from vigilloo.graph import GraphRows, Project, graph_rows, load_project
from vigilloo.graph_export import export_graphml, export_json
from vigilloo.models import EdgeRow, NodeRow
from vigilloo.store import connect, graph_for_project, record_scan
from vigilloo.workspace import Workspace

FIXTURE = Path("tests/fixtures/laravel-minimal")

_GRAPHML_NS = "{http://graphml.graphdrawing.org/xmlns}"


def _rows(project: Project) -> GraphRows:
    """Build rows with a synthetic file_id per path, standing in for the store's."""
    paths = sorted(set(project.files) | set(project.blade) | set(project.failed))
    return graph_rows(project, 1, {path: index for index, path in enumerate(paths, 1)})


def _fixture_rows() -> GraphRows:
    return _rows(load_project(FIXTURE))


def _graph(xml: str) -> ET.Element:
    graph = ET.fromstring(xml).find(f"{_GRAPHML_NS}graph")
    assert graph is not None
    return graph


# ─── Determinism ─────────────────────────────────────────────────────────────


def test_two_json_exports_of_the_same_project_are_byte_identical() -> None:
    """Invariant 8, over the artefact a consumer actually diffs."""
    first, second = _fixture_rows(), _fixture_rows()

    assert (
        export_json(first.nodes, first.edges).encode()
        == export_json(second.nodes, second.edges).encode()
    )


def test_two_graphml_exports_of_the_same_project_are_byte_identical() -> None:
    first, second = _fixture_rows(), _fixture_rows()

    assert (
        export_graphml(first.nodes, first.edges).encode()
        == export_graphml(second.nodes, second.edges).encode()
    )


def test_export_order_does_not_follow_input_order() -> None:
    """The exporter imposes its own order; it never inherits its caller's.

    Rows read back from SQLite arrive in whatever order the query planner chose, so an
    exporter that trusted its input would produce a different file from the same graph
    depending on which side it was handed.
    """
    rows = _fixture_rows()
    shuffled = list(reversed(rows.nodes)), list(reversed(rows.edges))

    assert export_json(*shuffled) == export_json(rows.nodes, rows.edges)
    assert export_graphml(*shuffled) == export_graphml(rows.nodes, rows.edges)


# ─── JSON ────────────────────────────────────────────────────────────────────


def test_json_carries_every_node_and_every_edge() -> None:
    rows = _fixture_rows()
    payload = json.loads(export_json(rows.nodes, rows.edges))

    assert payload["format"] == "vigilloo.graph"
    assert len(payload["nodes"]) == len(rows.nodes)
    assert len(payload["edges"]) == len(rows.edges)


def test_json_round_trips_back_into_the_row_types() -> None:
    """Lossless is the whole claim of this format, so it is asserted as a round trip.

    Every object is the row's own field names, so a consumer rebuilds a row by splatting it -
    and any field the exporter silently dropped comes back as a default and fails the compare.
    """
    rows = _fixture_rows()
    payload = json.loads(export_json(rows.nodes, rows.edges))

    nodes = [NodeRow(**obj) for obj in payload["nodes"]]
    edges = [EdgeRow(**obj) for obj in payload["edges"]]
    assert sorted(nodes, key=lambda n: n.id) == sorted(rows.nodes, key=lambda n: n.id)
    assert sorted(edges, key=repr) == sorted(rows.edges, key=repr)


def test_json_omits_absent_fields_rather_than_writing_null() -> None:
    """A file node has no span, and `"start_line": null` is noise on every one of them."""
    rows = _fixture_rows()
    payload = json.loads(export_json(rows.nodes, rows.edges))

    file_node = next(obj for obj in payload["nodes"] if obj["kind"] == "file")
    assert "start_line" not in file_node
    assert None not in file_node.values()


def test_json_keeps_a_routes_list_valued_attributes() -> None:
    """The kind-specific bag is where the Laravel facts live; flattening it would lose them."""
    rows = _fixture_rows()
    payload = json.loads(export_json(rows.nodes, rows.edges))

    route = next(obj for obj in payload["nodes"] if obj["kind"] == "route")
    assert route["attrs"]["verbs"]
    assert route["attrs"]["action"]


# ─── GraphML ─────────────────────────────────────────────────────────────────


def test_graphml_is_well_formed_and_names_the_graphml_namespace() -> None:
    rows = _fixture_rows()

    root = ET.fromstring(export_graphml(rows.nodes, rows.edges))
    assert root.tag == f"{_GRAPHML_NS}graphml"
    assert _graph(export_graphml(rows.nodes, rows.edges)).get("edgedefault") == "directed"


def test_graphml_holds_every_node_and_edge_and_no_edge_dangles() -> None:
    rows = _fixture_rows()
    graph = _graph(export_graphml(rows.nodes, rows.edges))

    ids = {node.get("id") for node in graph.findall(f"{_GRAPHML_NS}node")}
    edges = graph.findall(f"{_GRAPHML_NS}edge")
    assert ids == {node.id for node in rows.nodes}
    assert len(edges) == len(rows.edges)
    for edge in edges:
        assert edge.get("source") in ids and edge.get("target") in ids


def test_every_data_element_references_a_declared_key() -> None:
    """The GraphML schema's own rule, and the one a viewer rejects the file over."""
    rows = _fixture_rows()
    root = ET.fromstring(export_graphml(rows.nodes, rows.edges))

    declared = {key.get("id"): key for key in root.findall(f"{_GRAPHML_NS}key")}
    assert declared, "no <key> declarations were emitted"
    for key in declared.values():
        assert key.get("for") in ("node", "edge")
        assert key.get("attr.name") and key.get("attr.type")

    graph = _graph(export_graphml(rows.nodes, rows.edges))
    used = 0
    for owner in ("node", "edge"):
        for element in graph.findall(f"{_GRAPHML_NS}{owner}"):
            for data in element.findall(f"{_GRAPHML_NS}data"):
                key = declared[data.get("key", "")]
                assert key.get("for") == owner
                used += 1
    assert used > 0


def test_graphml_declares_keys_before_the_graph_that_uses_them() -> None:
    """Element order is part of the schema, not presentation: key* then graph."""
    rows = _fixture_rows()
    root = ET.fromstring(export_graphml(rows.nodes, rows.edges))

    tags = [child.tag for child in root]
    assert tags[-1] == f"{_GRAPHML_NS}graph"
    assert set(tags[:-1]) == {f"{_GRAPHML_NS}key"}


def test_graphml_writes_no_empty_element_for_a_missing_attribute() -> None:
    """GraphML has no null, and an empty <data> claims the value is the empty string."""
    rows = _fixture_rows()
    graph = _graph(export_graphml(rows.nodes, rows.edges))

    file_node = next(
        node
        for node in graph.findall(f"{_GRAPHML_NS}node")
        if any(data.text == "file" for data in node.findall(f"{_GRAPHML_NS}data"))
    )
    keys = {data.get("key") for data in file_node.findall(f"{_GRAPHML_NS}data")}
    assert "n_start_line" not in keys
    assert all(data.text for data in file_node.findall(f"{_GRAPHML_NS}data"))


# ─── The store round trip ────────────────────────────────────────────────────


def test_a_graph_read_back_from_the_store_exports_identically(fixture_project: Path) -> None:
    """The whole reason export takes rows and not a GraphRows.

    A `vigilloo graph export` over a project scanned yesterday must produce the file a scan
    today would, or the two forms of the same command answer differently.
    """
    workspace = Workspace.open(fixture_project)
    project = load_project(workspace.root)
    conn = connect(workspace)
    record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)

    project_id = conn.execute("SELECT id FROM projects").fetchone()[0]
    stored_nodes, stored_edges = graph_for_project(conn, project_id)
    rows = graph_rows(
        project,
        project_id,
        {
            Path(path): file_id
            for file_id, path in conn.execute(
                "SELECT id, path FROM files WHERE project_id = ?", (project_id,)
            )
        },
    )

    assert export_json(stored_nodes, stored_edges) == export_json(rows.nodes, rows.edges)
    assert export_graphml(stored_nodes, stored_edges) == export_graphml(rows.nodes, rows.edges)


def test_a_second_read_of_the_store_exports_the_same_bytes(fixture_project: Path) -> None:
    workspace = Workspace.open(fixture_project)
    conn = connect(workspace)
    record_scan(
        conn,
        load_project(workspace.root),
        [],
        engine_version="0.0.1",
        ruleset_hash="rs1",
        duration_ms=1,
    )
    project_id = conn.execute("SELECT id FROM projects").fetchone()[0]

    first = graph_for_project(conn, project_id)
    second = graph_for_project(conn, project_id)
    assert export_json(*first) == export_json(*second)
    assert export_graphml(*first) == export_graphml(*second)
