"""Reading findings back: the round trip, and what identity survives it.

The scan under test is the real one over the Laravel fixture, not a hand-built finding. The
point of a round trip is that whatever the engine produces comes back, and a fixture written
by hand only proves the store can return what a test just taught it.
"""

import sqlite3
from pathlib import Path

import pytest

from vigilloo.graph import load_project
from vigilloo.models import Finding, PathStep, Span, WalkStats
from vigilloo.rules import scan_project
from vigilloo.store import StoredFinding, connect, findings_for_scan, record_scan
from vigilloo.workspace import Workspace


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


def test_every_finding_the_scan_produced_comes_back(fixture_project: Path) -> None:
    conn, produced, scan_id = _scan(fixture_project)

    stored = findings_for_scan(conn, scan_id)
    assert len(stored) == len(produced)
    assert {f.id for f in stored} == {f.id for f in produced}
    assert produced, "the fixture must produce findings or this asserts nothing"


def test_each_finding_keeps_its_whole_evidence_path(fixture_project: Path) -> None:
    """Invariant 2 across the storage boundary: a path that loses a step is a different path."""
    conn, produced, scan_id = _scan(fixture_project)
    stored = _by_id(findings_for_scan(conn, scan_id))

    for finding in produced:
        path = stored[finding.id].path
        assert [s.role for s in path] == [s.role for s in finding.evidence_path]
        assert [s.snippet for s in path] == [s.snippet for s in finding.evidence_path]
        assert [s.note for s in path] == [s.note for s in finding.evidence_path]
        assert [s.line for s in path] == [s.span.start_line for s in finding.evidence_path]
        assert [s.file for s in path] == [s.span.file for s in finding.evidence_path]
        assert [s.step for s in path] == list(range(len(finding.evidence_path)))


def test_the_scalar_fields_survive(fixture_project: Path) -> None:
    conn, produced, scan_id = _scan(fixture_project)
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


def test_identity_is_recoverable_from_what_was_stored(fixture_project: Path) -> None:
    """The round trip that decides whether baselines work.

    `Finding.id` and `.fingerprint` are derived from the rule, the file, the start line and
    each step's role, file, line and snippet - every one of which the store keeps. Rebuilding
    a Finding from the stored row must therefore reproduce both hashes exactly. If it did not,
    a suppression written against one scan would stop matching in the next, and nothing else
    in the suite would notice.

    The rebuilt spans use the stored line for all four numbers. That is legitimate here and
    only here: neither hash reads a column, which is why the store is allowed not to keep one.
    """
    conn, produced, scan_id = _scan(fixture_project)

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


def test_a_step_is_anchored_to_the_graph_node_it_happened_in(fixture_project: Path) -> None:
    """Not a line number: a stored step names a node, so a reader can traverse from it."""
    conn, _, scan_id = _scan(fixture_project)

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
        rule_id="php.sql-injection",
        severity="critical",
        title="t",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep("sink", span, "DB::select(...)", "", "php.sql-injection"),),
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
            rule_id="php.sql-injection",
            severity="critical",
            title="t",
            cwe=(),
            span=Span(Path("a.php"), 1, 0, 1, 1),
            evidence_path=(),
        )


def test_reading_a_finding_whose_path_was_lost_is_an_error_not_a_shrug(
    fixture_project: Path,
) -> None:
    """A pathless finding is something the engine cannot produce, so returning one would lie."""
    conn, _, scan_id = _scan(fixture_project)
    with conn:
        conn.execute("DELETE FROM evidence_paths WHERE scan_id = ?", (scan_id,))

    with pytest.raises(ValueError, match="no stored evidence path"):
        findings_for_scan(conn, scan_id)


def test_two_reads_of_one_scan_are_identical(fixture_project: Path) -> None:
    """Invariant 8 reaches the store: unordered SQL is as nondeterministic as an unsorted set."""
    conn, _, scan_id = _scan(fixture_project)
    assert findings_for_scan(conn, scan_id) == findings_for_scan(conn, scan_id)


def test_findings_come_back_in_source_order(fixture_project: Path) -> None:
    conn, _, scan_id = _scan(fixture_project)
    stored = findings_for_scan(conn, scan_id)

    keys = [(str(f.file), f.start_line, f.id) for f in stored]
    assert keys == sorted(keys)
