"""The machine-readable output Phase 2 measures precision by diffing."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.models import Coverage, Finding, PathStep, Span
from vigilloo.report.document import ReportDocument, build_document
from vigilloo.report.json_report import render_json

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def _document() -> ReportDocument:
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(role="source", span=span, snippet="$r->input('q')", note="request"),
            PathStep(role="sink", span=span, snippet="whereRaw($q)", rule_id="laravel.raw-query"),
        ),
        remediation="Bind the parameter.",
    )
    coverage = Coverage(
        files_discovered=4,
        files_unreadable=0,
        files_with_errors=1,
        calls_resolved=3,
        calls_unresolved=1,
    )
    return build_document([finding], coverage, engine_version="0.1.0", ruleset_hash="abc")


def test_finding_carries_its_whole_evidence_path() -> None:
    """Invariant 2. A finding serialised without its path is not a finding."""
    payload = json.loads(render_json(_document()))
    (finding,) = payload["findings"]
    assert [step["role"] for step in finding["evidence_path"]] == ["source", "sink"]
    assert finding["evidence_path"][0]["snippet"] == "$r->input('q')"
    assert finding["fingerprint"]
    assert finding["id"]


def test_coverage_is_present_even_when_perfect() -> None:
    """Invariant 4. Coverage is reported, never hidden, and a consumer must
    never have to treat its absence as meaning 100%.
    """
    coverage = Coverage(
        files_discovered=2,
        files_unreadable=0,
        files_with_errors=0,
        calls_resolved=2,
        calls_unresolved=0,
    )
    doc = build_document([], coverage, engine_version="0.1.0", ruleset_hash="abc")
    payload = json.loads(render_json(doc))
    assert payload["coverage"]["parse_success_rate"] == 1.0
    assert payload["coverage"]["files_parsed"] == 2
    assert payload["findings"] == []


def test_paths_are_posix_so_output_does_not_depend_on_the_host() -> None:
    """A backslash on Windows would make the same codebase produce different
    bytes on different machines, and the corpus harness compares across them.
    """
    payload = json.loads(render_json(_document()))
    assert payload["findings"][0]["location"]["file"] == "app/X.php"
    assert "\\" not in render_json(_document())


def test_two_scans_of_one_project_are_byte_identical(tmp_path: Path) -> None:
    """Invariant 8, end to end through the real CLI.

    Not a unit test of the serialiser: the whole point is that nothing
    anywhere in the pipeline - dict ordering, a set iteration, a temp path,
    a duration - reaches the bytes.
    """
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    first = runner.invoke(app, ["scan", str(root), "--format", "json"])
    second = runner.invoke(app, ["scan", str(root), "--format", "json"])

    assert first.exit_code == 1
    assert second.exit_code == 1
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["findings"]


def test_stdout_is_only_json(tmp_path: Path) -> None:
    """A warning printed to stdout would make the output unparseable.

    The scan prints several coverage caveats; under --format json every one
    of them belongs on stderr. This is the guard that catches a future
    console.print added to the scan path without thinking about it.
    """
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    result = runner.invoke(app, ["scan", str(root), "--format", "json"])

    json.loads(result.stdout)  # raises if anything else reached stdout
