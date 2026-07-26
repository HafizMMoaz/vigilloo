from pathlib import Path

from vigilloo.graph import Project
from vigilloo.models import Finding, PathStep, Span
from vigilloo.parser import parse_source
from vigilloo.store import connect, record_scan
from vigilloo.workspace import Workspace

_REL_PATH = Path("app/Http/Controllers/OrderController.php")


def _span(line: int) -> Span:
    return Span(_REL_PATH, line, 0, line, 10)


def _project(root: Path, *, failed: list[Path] | None = None) -> Project:
    parsed = parse_source(_REL_PATH, b"<?php\nclass OrderController {}\n")
    return Project(
        root=root,
        files={_REL_PATH: parsed},
        digests={_REL_PATH: "deadbeef"},
        failed=failed or [],
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
    assert {"schema_meta", "projects", "scans", "files", "findings", "evidence_paths"} <= tables

    version = conn.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()[0]
    assert version == "1"


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


def test_a_file_that_failed_to_parse_marks_the_scan_partial(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    conn = connect(workspace)
    project = _project(workspace.root, failed=[Path("app/Broken.php")])

    scan_id = record_scan(
        conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )

    status, files_failed = conn.execute(
        "SELECT status, files_failed FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    assert status == "partial"
    assert files_failed == 1


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
