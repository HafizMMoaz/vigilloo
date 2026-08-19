"""Reading findings back: the round trip, and what identity survives it.

The scan under test is the real one over the Laravel fixture, not a hand-built finding. The
point of a round trip is that whatever the engine produces comes back, and a fixture written
by hand only proves the store can return what a test just taught it.
"""

import shutil
import sqlite3
from pathlib import Path

import pytest

from vigilloo.graph import load_project
from vigilloo.models import Finding, PathStep, Span, WalkStats
from vigilloo.rules import scan_project
from vigilloo.store import (
    StoredFinding,
    connect,
    findings_by_fingerprint,
    findings_for_scan,
    latest_scan,
    project_id_for,
    record_scan,
)
from vigilloo.workspace import Workspace


@pytest.fixture
def project_root(fixture_project: Path, tmp_path: Path) -> Path:
    """A private copy of the fixture tree, one per test.

    `fixture_project` is session-scoped, so every test that scans it shares one
    `.vigilloo/vigilloo.db`. That is fine while each test reads only the scan it just recorded,
    and stops being fine here: `findings_by_fingerprint` deliberately spans every scan of the
    project, so it sees rows other tests wrote - including the ones the corrupt-path test
    deletes. The isolation belongs to the tests that need it rather than to the shared fixture.
    """
    root = tmp_path / "project"
    shutil.copytree(fixture_project, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def _scan(root: Path) -> tuple[sqlite3.Connection, list[Finding], int]:
    workspace = Workspace.open(root)
    project = load_project(workspace.root)
    findings = scan_project(project, WalkStats())
    conn = connect(workspace)
    scan_id = record_scan(
        conn, project, findings, engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )
    return conn, findings, scan_id


def _by_id(findings: list[StoredFinding]) -> dict[str, StoredFinding]:
    return {finding.id: finding for finding in findings}


def test_every_finding_the_scan_produced_comes_back(project_root: Path) -> None:
    conn, produced, scan_id = _scan(project_root)

    stored = findings_for_scan(conn, scan_id)
    assert len(stored) == len(produced)
    assert {f.id for f in stored} == {f.id for f in produced}
    assert produced, "the fixture must produce findings or this asserts nothing"


def test_each_finding_keeps_its_whole_evidence_path(project_root: Path) -> None:
    """Invariant 2 across the storage boundary: a path that loses a step is a different path."""
    conn, produced, scan_id = _scan(project_root)
    stored = _by_id(findings_for_scan(conn, scan_id))

    for finding in produced:
        path = stored[finding.id].path
        assert [s.role for s in path] == [s.role for s in finding.evidence_path]
        assert [s.snippet for s in path] == [s.snippet for s in finding.evidence_path]
        assert [s.note for s in path] == [s.note for s in finding.evidence_path]
        assert [s.line for s in path] == [s.span.start_line for s in finding.evidence_path]
        assert [s.file for s in path] == [s.span.file for s in finding.evidence_path]
        assert [s.step for s in path] == list(range(len(finding.evidence_path)))


def test_the_scalar_fields_survive(project_root: Path) -> None:
    conn, produced, scan_id = _scan(project_root)
    stored = _by_id(findings_for_scan(conn, scan_id))

    for finding in produced:
        row = stored[finding.id]
        assert row.rule_id == finding.rule_id
        assert row.severity == finding.severity
        assert row.title == finding.title
        assert row.remediation == finding.remediation
        assert row.cwe == finding.cwe
        assert row.file == finding.span.file
        assert row.start_line == finding.span.start_line
        assert row.fingerprint == finding.fingerprint


def test_identity_is_recoverable_from_what_was_stored(project_root: Path) -> None:
    """The round trip that decides whether baselines work.

    `Finding.id` and `.fingerprint` are derived from the rule, the file, the start line and
    each step's role, file, line and snippet - every one of which the store keeps. Rebuilding
    a Finding from the stored row must therefore reproduce both hashes exactly. If it did not,
    a suppression written against one scan would stop matching in the next, and nothing else
    in the suite would notice.

    The rebuilt spans use the stored line for all four numbers. That is legitimate here and
    only here: neither hash reads a column, which is why the store is allowed not to keep one.
    """
    conn, produced, scan_id = _scan(project_root)

    for row in findings_for_scan(conn, scan_id):
        assert row.file is not None
        rebuilt = Finding(
            rule_id=row.rule_id,
            severity=row.severity,
            title=row.title,
            cwe=row.cwe,
            span=_span(row.file, row.start_line),
            evidence_path=tuple(
                PathStep(role=s.role, span=_span(s.file, s.line), snippet=s.snippet, note=s.note)
                for s in row.path
            ),
        )
        assert rebuilt.id == row.id
        assert rebuilt.fingerprint == row.fingerprint


def _span(file: Path | None, line: int | None) -> Span:
    return Span(file or Path(""), line or 0, 0, line or 0, 0)


def test_a_step_is_anchored_to_the_graph_node_it_happened_in(project_root: Path) -> None:
    """Not a line number: a stored step names a node, so a reader can traverse from it."""
    conn, _, scan_id = _scan(project_root)

    anchors = [
        step.node_id
        for finding in findings_for_scan(conn, scan_id)
        for step in finding.path
        if step.node_id is not None
    ]
    assert anchors, "no step resolved to a node"

    # Every anchor is a node that exists, and the kinds are ones a traversal can use: a step
    # inside a controller action resolves to that method, never only to the file around it.
    kinds = set()
    for node_id in anchors:
        row = conn.execute("SELECT kind FROM nodes WHERE id = ?", (node_id,)).fetchone()
        assert row is not None, f"step anchored to {node_id}, which is not a node"
        kinds.add(row[0])

    assert kinds <= {"method", "class", "route", "file"}
    assert "method" in kinds


def test_a_step_resolves_to_the_innermost_node_covering_it(tmp_path: Path) -> None:
    """A method inside a class must win over the class, or every step anchors to the file."""
    root = tmp_path / "app"
    (root / "app").mkdir(parents=True)
    (root / "app" / "Thing.php").write_bytes(
        b"<?php\nnamespace App;\nclass Thing {\n  public function go($q) {\n"
        b'    return \\DB::select("select * from t where a = $q");\n  }\n}\n'
    )
    workspace = Workspace.open(root)
    project = load_project(workspace.root)
    conn = connect(workspace)

    span = Span(Path("app/Thing.php"), 5, 4, 5, 20)
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="t",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep("sink", span, "DB::select(...)", "", "laravel.raw-query"),),
    )
    scan_id = record_scan(
        conn, project, [finding], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )

    (step,) = findings_for_scan(conn, scan_id)[0].path
    kind, fqn = conn.execute("SELECT kind, fqn FROM nodes WHERE id = ?", (step.node_id,)).fetchone()
    assert (kind, fqn) == ("method", "App\\Thing::go")


def test_a_finding_with_no_path_cannot_be_built_let_alone_stored() -> None:
    """Invariant 2 is enforced before the store ever sees it, which is the right place."""
    with pytest.raises(ValueError, match="empty evidence path"):
        Finding(
            rule_id="laravel.raw-query",
            severity="critical",
            title="t",
            cwe=(),
            span=Span(Path("a.php"), 1, 0, 1, 1),
            evidence_path=(),
        )


def test_reading_a_finding_whose_path_was_lost_is_an_error_not_a_shrug(
    project_root: Path,
) -> None:
    """A pathless finding is something the engine cannot produce, so returning one would lie."""
    conn, _, scan_id = _scan(project_root)
    with conn:
        conn.execute("DELETE FROM evidence_paths WHERE scan_id = ?", (scan_id,))

    with pytest.raises(ValueError, match="no stored evidence path"):
        findings_for_scan(conn, scan_id)


def test_two_reads_of_one_scan_are_identical(project_root: Path) -> None:
    """Invariant 8 reaches the store: unordered SQL is as nondeterministic as an unsorted set."""
    conn, _, scan_id = _scan(project_root)
    assert findings_for_scan(conn, scan_id) == findings_for_scan(conn, scan_id)


def test_findings_come_back_in_source_order(project_root: Path) -> None:
    conn, _, scan_id = _scan(project_root)
    stored = findings_for_scan(conn, scan_id)

    keys = [(str(f.file), f.start_line, f.id) for f in stored]
    assert keys == sorted(keys)


# ─── Lookups (TASK-012) ──────────────────────────────────────────────────────


def test_latest_scan_returns_the_second_of_two(project_root: Path) -> None:
    workspace = Workspace.open(project_root)
    project = load_project(workspace.root)
    conn = connect(workspace)

    first = record_scan(
        conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )
    second = record_scan(
        conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )

    project_id = project_id_for(conn, workspace.root)
    assert project_id is not None
    assert first != second
    assert latest_scan(conn, project_id) == second


def test_latest_scan_is_keyed_on_the_insert_order_not_the_clock(project_root: Path) -> None:
    """A long scan finishing after a short one still started earlier by the clock.

    `started_at` is the finish time minus the measured duration, so the second scan below
    carries the earlier start. "Latest" must still mean the one recorded last.
    """
    workspace = Workspace.open(project_root)
    project = load_project(workspace.root)
    conn = connect(workspace)

    record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)
    slow = record_scan(
        conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=600_000
    )

    project_id = project_id_for(conn, workspace.root)
    assert project_id is not None
    starts = [row[0] for row in conn.execute("SELECT started_at FROM scans ORDER BY id")]
    assert starts[1] < starts[0], "the fixture for this test no longer sets up the case"
    assert latest_scan(conn, project_id) == slow


def test_a_project_that_was_never_scanned_has_no_id_and_no_latest_scan(tmp_path: Path) -> None:
    """A first run is the ordinary case, not an error."""
    conn = connect(Workspace.open(tmp_path))
    assert project_id_for(conn, tmp_path) is None


def test_a_fingerprint_lookup_spans_every_scan_that_saw_it(project_root: Path) -> None:
    conn, produced, _ = _scan(project_root)
    workspace = Workspace.open(project_root)
    project = load_project(workspace.root)
    second = record_scan(
        conn, project, produced, engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1
    )
    project_id = project_id_for(conn, workspace.root)
    assert project_id is not None

    fingerprint = produced[0].fingerprint
    history = findings_by_fingerprint(conn, project_id, fingerprint)

    assert len(history) == 2
    assert [f.scan_id for f in history] == sorted(f.scan_id for f in history)
    assert history[-1].scan_id == second
    assert {f.fingerprint for f in history} == {fingerprint}
    # first_seen_scan is what "when did this get introduced" reads, and it must not move.
    assert len({f.first_seen_scan for f in history}) == 1
    # Each scan's copy carries its own full path, not a shared one.
    assert all(f.path for f in history)


def test_a_fingerprint_lookup_is_scoped_to_its_project(project_root: Path) -> None:
    conn, produced, _ = _scan(project_root)
    project_id = project_id_for(conn, Workspace.open(project_root).root)
    assert project_id is not None

    assert findings_by_fingerprint(conn, project_id + 1, produced[0].fingerprint) == []


def test_an_unknown_fingerprint_returns_nothing(project_root: Path) -> None:
    conn, _, _ = _scan(project_root)
    project_id = project_id_for(conn, Workspace.open(project_root).root)
    assert project_id is not None

    assert findings_by_fingerprint(conn, project_id, "0" * 16) == []


def test_the_lookups_use_their_indexes(project_root: Path) -> None:
    """The acceptance criterion for TASK-012, asserted rather than assumed.

    An index that exists and is not chosen is an index that does nothing, and nothing else in
    the suite would notice at fixture scale - the tables are small enough that a full scan is
    fast and correct. This is the only place the plan itself is the subject.
    """
    conn, _, _ = _scan(project_root)

    latest_plan = _plan(conn, "SELECT id FROM scans WHERE project_id = ? ORDER BY id DESC LIMIT 1")
    assert "idx_scans_project" in latest_plan
    assert "SCAN scans" not in latest_plan

    fp_plan = _plan(
        conn,
        "SELECT fi.id FROM findings fi LEFT JOIN files f ON f.id = fi.file_id "
        "WHERE fi.project_id = ? AND fi.fingerprint = ?",
    )
    assert "idx_findings_fp" in fp_plan


def _plan(conn: sqlite3.Connection, sql: str) -> str:
    params = tuple([None] * sql.count("?"))
    return "\n".join(str(row[3]) for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}", params))
