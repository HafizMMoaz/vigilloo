import hashlib
import sqlite3
from pathlib import Path

import pytest

from vigilloo.graph import Project, load_project
from vigilloo.models import Finding, PathStep, Span
from vigilloo.parser import parse_source
from vigilloo.store import EdgeRow, NodeRow, connect, insert_edges, insert_nodes, record_scan
from vigilloo.workspace import Workspace

_REL_PATH = Path("app/Http/Controllers/OrderController.php")


def _span(line: int) -> Span:
    return Span(_REL_PATH, line, 0, line, 10)


def _project(
    root: Path,
    *,
    failed: list[Path] | None = None,
    source: bytes = b"<?php\nclass OrderController {}\n",
) -> Project:
    parsed = parse_source(_REL_PATH, source)
    return Project(
        root=root,
        files={_REL_PATH: parsed},
        digests={_REL_PATH: "deadbeef"},
        failed=failed or [],
        # Derived from the parse, exactly as load_project derives it, so a test cannot claim a
        # file failed to parse while handing the store a file that parsed clean.
        unparsed=[_REL_PATH] if parsed.has_errors else [],
    )


def _finding() -> Finding:
    steps = (
        PathStep("source", _span(5), "$request->input('q')", ""),
        PathStep("sink", _span(12), "DB::raw($q)", "", "php.sql-injection"),
    )
    return Finding(
        rule_id="php.sql-injection",
        severity="critical",
        title="SQL Injection",
        cwe=("CWE-89",),
        span=_span(12),
        evidence_path=steps,
    )


def test_connect_creates_the_schema_and_records_its_version(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)

    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "schema_meta",
        "projects",
        "scans",
        "files",
        "nodes",
        "edges",
        "findings",
        "evidence_paths",
    } <= tables

    version = conn.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()[0]
    assert version == "2"


def test_the_graph_tables_carry_their_five_indexes(tmp_path: Path) -> None:
    """docs/17-database names them; without them every traversal is a table scan."""
    conn = connect(Workspace.open(tmp_path))

    indexes = {
        row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    }
    assert {
        "idx_nodes_kind",
        "idx_nodes_fqn",
        "idx_nodes_file",
        "idx_edges_src",
        "idx_edges_dst",
    } <= indexes


def test_a_database_from_another_schema_version_is_refused_loudly(tmp_path: Path) -> None:
    """A silent version mismatch surfaces much later as "no such table"."""
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    with conn:
        conn.execute("UPDATE schema_meta SET value = '1' WHERE key = 'version'")
    conn.close()

    with pytest.raises(RuntimeError, match="schema version 1"):
        connect(workspace)


def test_reopening_an_existing_database_keeps_its_rows(tmp_path: Path) -> None:
    """The store is the one thing under .vigilloo/ that cannot be rebuilt on reopen."""
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    project = _project(workspace.root)
    finding = _finding()
    record_scan(
        conn, project, [finding], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=10
    )
    conn.close()

    reopened = connect(workspace)
    ids = [row[0] for row in reopened.execute("SELECT id FROM findings")]
    assert ids == [finding.id]


def test_record_scan_writes_the_finding_and_every_evidence_step(tmp_path: Path) -> None:
    """Invariant 2 at the storage boundary: no path, no finding."""
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    project = _project(workspace.root)
    finding = _finding()

    scan_id = record_scan(
        conn, project, [finding], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=5
    )

    row = conn.execute(
        "SELECT rule_id, severity, scan_id FROM findings WHERE id = ?", (finding.id,)
    ).fetchone()
    assert row == (finding.rule_id, finding.severity, scan_id)

    steps = conn.execute(
        "SELECT step, role, snippet FROM evidence_paths WHERE finding_id = ? ORDER BY step",
        (finding.id,),
    ).fetchall()
    assert steps == [(0, "source", "$request->input('q')"), (1, "sink", "DB::raw($q)")]


def test_first_seen_scan_survives_into_a_later_scan_of_the_same_finding(tmp_path: Path) -> None:
    """The spec-correction key (fingerprint) and the derived column together."""
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    project = _project(workspace.root)
    finding = _finding()

    first_scan_id = record_scan(
        conn, project, [finding], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )
    second_scan_id = record_scan(
        conn, project, [finding], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )
    assert second_scan_id != first_scan_id

    first_seen = conn.execute(
        "SELECT first_seen_scan FROM findings WHERE scan_id = ? AND id = ?",
        (second_scan_id, finding.id),
    ).fetchone()[0]
    assert first_seen == first_scan_id


def test_a_file_that_failed_to_read_marks_the_scan_partial(tmp_path: Path) -> None:
    """Invariant 4: an unreadable file is a coverage gap and gets its own row saying so."""
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    unreadable = Path("app/Broken.php")
    project = _project(workspace.root, failed=[unreadable])

    scan_id = record_scan(
        conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )

    status, files_failed = conn.execute(
        "SELECT status, files_failed FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    assert status == "partial"
    assert files_failed == 1

    parse_state = conn.execute(
        "SELECT parse_state FROM files WHERE path = ?", (unreadable.as_posix(),)
    ).fetchone()
    assert parse_state == ("failed",)


def test_a_file_that_failed_to_parse_marks_the_scan_partial(tmp_path: Path) -> None:
    """Invariant 4: a file that parsed with errors is read and counted, and still partial."""
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    project = _project(
        workspace.root, source=b"<?php\nclass OrderController { public function x( {\n"
    )
    assert project.unparsed == [_REL_PATH]

    scan_id = record_scan(
        conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )

    status = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]
    assert status == "partial"

    parse_state = conn.execute(
        "SELECT parse_state FROM files WHERE path = ?", (_REL_PATH.as_posix(),)
    ).fetchone()[0]
    assert parse_state == "partial"


def test_recording_a_scan_for_the_same_root_twice_reuses_the_project_row(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    project = _project(workspace.root)

    record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)
    record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)

    rows = conn.execute(
        "SELECT id FROM projects WHERE root_path = ?", (str(project.root),)
    ).fetchall()
    assert len(rows) == 1


def _stored_project(tmp_path: Path) -> tuple[sqlite3.Connection, int, int]:
    """A connection with one project row and one file row, for the graph tests.

    The scan it records also writes that project's own graph, so the tests below scope every
    assertion to the ids they insert rather than counting whole tables. They exercise the
    batch-insert primitives; what `record_scan` derives on its own is `test_graph_rows.py`.
    """
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    record_scan(
        conn,
        _project(workspace.root),
        [],
        engine_version="0.0.1",
        ruleset_hash="rs1",
        duration_ms=1,
    )
    project_id = conn.execute("SELECT id FROM projects").fetchone()[0]
    file_id = conn.execute("SELECT id FROM files").fetchone()[0]
    return conn, project_id, file_id


def test_ten_thousand_nodes_go_in_as_one_batch(tmp_path: Path) -> None:
    """The acceptance case for docs/23-dev-guide section Performance: no N+1 insert."""
    conn, project_id, file_id = _stored_project(tmp_path)
    nodes = [
        NodeRow(
            id=f"node-{index:05d}",
            kind="method",
            name=f"handle{index}",
            fqn=f"App\\Jobs\\Job{index}::handle",
            file_id=file_id,
        )
        for index in range(10_000)
    ]

    with conn:
        insert_nodes(conn, project_id, nodes)

    count = conn.execute("SELECT COUNT(*) FROM nodes WHERE id LIKE 'node-%'").fetchone()[0]
    assert count == 10_000


def test_a_batch_that_violates_a_constraint_writes_none_of_it(tmp_path: Path) -> None:
    """One transaction, not one per row: a rejected node takes its whole batch with it."""
    conn, project_id, _ = _stored_project(tmp_path)
    good = [NodeRow(id=f"node-{index}", kind="class") for index in range(10)]
    dangling = NodeRow(id="node-orphan", kind="class", file_id=987654)

    with pytest.raises(sqlite3.IntegrityError), conn:
        insert_nodes(conn, project_id, [*good, dangling])

    assert conn.execute("SELECT COUNT(*) FROM nodes WHERE id LIKE 'node-%'").fetchone()[0] == 0


def test_reinserting_a_content_derived_id_is_a_no_op(tmp_path: Path) -> None:
    """Invariant 3: the same node re-derived is the same node, not a conflict."""
    conn, project_id, file_id = _stored_project(tmp_path)
    node = NodeRow(
        id="c0ffee",
        kind="class",
        name="OrderController",
        fqn="App\\Http\\Controllers\\OrderController",
        file_id=file_id,
        start_line=2,
    )

    with conn:
        insert_nodes(conn, project_id, [node])
        insert_nodes(conn, project_id, [node])

    rows = conn.execute("SELECT id, fqn, start_line FROM nodes WHERE id = ?", (node.id,)).fetchall()
    assert rows == [(node.id, node.fqn, 2)]


def test_nodes_and_edges_round_trip_with_their_attributes(tmp_path: Path) -> None:
    conn, project_id, file_id = _stored_project(tmp_path)
    source = NodeRow(id="src", kind="method", fqn="App\\A::index", file_id=file_id)
    target = NodeRow(id="dst", kind="method", fqn="App\\B::find", file_id=file_id)
    edge = EdgeRow(
        src_id=source.id,
        dst_id=target.id,
        kind="CALLS",
        confidence=0.9,
        resolution="facade",
        # Deliberately not in key order: the store sorts, so the column is byte-identical
        # for the same attributes however the caller happened to build them (invariant 8).
        attrs={"arg_index": 2, "alias": "DB"},
    )

    with conn:
        insert_nodes(conn, project_id, [source, target])
        insert_edges(conn, project_id, [edge])

    stored = conn.execute(
        "SELECT src_id, dst_id, kind, confidence, resolution, attrs FROM edges WHERE src_id = ?",
        (source.id,),
    ).fetchall()
    assert stored == [("src", "dst", "CALLS", 0.9, "facade", '{"alias": "DB", "arg_index": 2}')]

    fqns = [
        row[0]
        for row in conn.execute("SELECT fqn FROM nodes WHERE id IN ('src', 'dst') ORDER BY id")
    ]
    assert fqns == ["App\\B::find", "App\\A::index"]


def test_an_edge_to_an_unknown_node_is_rejected(tmp_path: Path) -> None:
    """The graph must not hold an edge to a node that does not exist."""
    conn, project_id, _ = _stored_project(tmp_path)
    source = NodeRow(id="src", kind="method")

    with pytest.raises(sqlite3.IntegrityError), conn:
        insert_nodes(conn, project_id, [source])
        insert_edges(conn, project_id, [EdgeRow(src_id="src", dst_id="missing", kind="CALLS")])


def test_the_stored_digest_is_of_the_blade_template_not_its_rewritten_php(tmp_path: Path) -> None:
    """files.sha256 digests the file on disk, which for Blade is not ParsedFile.source."""
    workspace = Workspace.open(tmp_path)
    php_rel = Path("app/Plain.php")
    php_source = b"<?php\nclass Plain {}\n"
    (workspace.root / php_rel).parent.mkdir(parents=True)
    (workspace.root / php_rel).write_bytes(php_source)
    blade_rel = Path("resources/views/profile.blade.php")
    template = b"<h1>{{ $name }}</h1>\n"
    (workspace.root / blade_rel).parent.mkdir(parents=True)
    (workspace.root / blade_rel).write_bytes(template)

    project = load_project(workspace.root)
    conn = connect(workspace)
    record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)

    digests = dict(conn.execute("SELECT path, sha256 FROM files"))
    assert digests[php_rel.as_posix()] == hashlib.sha256(php_source).hexdigest()
    assert digests[blade_rel.as_posix()] == hashlib.sha256(template).hexdigest()
    rewritten = hashlib.sha256(project.blade[blade_rel].source).hexdigest()
    assert digests[blade_rel.as_posix()] != rewritten
