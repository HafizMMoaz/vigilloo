"""Tests for SARIF 2.1.0 report serialization."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.models import Coverage, Finding, ParseFailure, PathStep, Span
from vigilloo.report.document import ReportDocument, build_document
from vigilloo.report.sarif import render_sarif

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")
UNPARSEABLE = Path("tests/fixtures/laravel-unparseable")


def _sample_document(has_failures: bool = False) -> ReportDocument:
    span = Span(
        file=Path("app/Http/Controllers/OrderController.php"),
        start_line=15,
        start_col=5,
        end_line=15,
        end_col=42,
    )
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="Raw Query Injection",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(
                role="source",
                span=span,
                snippet="$request->input('sort')",
                note="user input",
            ),
            PathStep(role="sink", span=span, snippet="DB::raw($sort)", rule_id="laravel.raw-query"),
        ),
        remediation="Use query parameter bindings instead of string interpolation.",
    )
    failures = (
        (ParseFailure(file=Path("broken.php"), kind="file", name=""),) if has_failures else ()
    )
    coverage = Coverage(
        files_discovered=10,
        files_unreadable=0,
        files_with_errors=1 if has_failures else 0,
        calls_resolved=8,
        calls_unresolved=2,
        parse_failures=failures,
    )
    return build_document(
        [finding], coverage, engine_version="0.1.0", ruleset_hash="fedcba9876543210"
    )


def test_sarif_schema_and_version() -> None:
    doc = _sample_document()
    payload = json.loads(render_sarif(doc))

    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert payload["version"] == "2.1.0"
    assert len(payload["runs"]) == 1

    run = payload["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "vigilloo"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) > 0


def test_sarif_rules_catalogue() -> None:
    doc = _sample_document()
    payload = json.loads(render_sarif(doc))
    rules = payload["runs"][0]["tool"]["driver"]["rules"]

    # Rule IDs must be unique and sorted
    rule_ids = [r["id"] for r in rules]
    assert rule_ids == sorted(rule_ids)

    # Check laravel.raw-query
    raw_query_rule = next(r for r in rules if r["id"] == "laravel.raw-query")
    assert raw_query_rule["defaultConfiguration"]["level"] == "error"
    assert raw_query_rule["properties"]["security-severity"] == "9.0"
    assert "CWE-89" in raw_query_rule["properties"]["tags"]
    assert "security" in raw_query_rule["properties"]["tags"]
    assert "help" in raw_query_rule
    assert "Remediation:" in raw_query_rule["help"]["text"]


def test_sarif_results_and_code_flows() -> None:
    doc = _sample_document()
    payload = json.loads(render_sarif(doc))
    results = payload["runs"][0]["results"]
    assert len(results) == 1

    res = results[0]
    assert res["ruleId"] == "laravel.raw-query"
    assert res["level"] == "error"
    assert res["partialFingerprints"]["vigillooFingerprint"]

    # Check location
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/Http/Controllers/OrderController.php"
    assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert loc["region"]["startLine"] == 15
    assert loc["region"]["snippet"]["text"] == "DB::raw($sort)"

    # Check code flow
    assert len(res["codeFlows"]) == 1
    thread_flows = res["codeFlows"][0]["threadFlows"]
    assert len(thread_flows) == 1
    steps = thread_flows[0]["locations"]
    assert len(steps) == 2
    assert steps[0]["executionOrder"] == 1
    assert steps[0]["importance"] == "essential"
    assert "[SOURCE]" in steps[0]["location"]["message"]["text"]
    assert steps[1]["executionOrder"] == 2
    assert steps[1]["importance"] == "essential"
    assert "[SINK]" in steps[1]["location"]["message"]["text"]


def test_sarif_invocation_success_and_failures() -> None:
    # Successful scan without parse failures
    clean_doc = _sample_document(has_failures=False)
    clean_payload = json.loads(render_sarif(clean_doc))
    inv_clean = clean_payload["runs"][0]["invocations"][0]
    assert inv_clean["executionSuccessful"] is True
    assert inv_clean["toolExecutionNotifications"] == []

    # Scan with parse failures
    broken_doc = _sample_document(has_failures=True)
    broken_payload = json.loads(render_sarif(broken_doc))
    inv_broken = broken_payload["runs"][0]["invocations"][0]
    assert inv_broken["executionSuccessful"] is False
    assert len(inv_broken["toolExecutionNotifications"]) == 1
    notif = inv_broken["toolExecutionNotifications"][0]
    assert "broken.php" in notif["message"]["text"]
    assert notif["level"] == "error"


def test_sarif_byte_identical_determinism() -> None:
    doc = _sample_document()
    output1 = render_sarif(doc)
    output2 = render_sarif(doc)
    assert output1 == output2


def test_cli_scan_format_sarif(tmp_path: Path) -> None:
    root = tmp_path / "project"
    import shutil

    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    res = runner.invoke(app, ["scan", str(root), "--format", "sarif"])
    assert res.exit_code in (0, 1)
    payload = json.loads(res.stdout)
    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(payload["runs"]) == 1
    assert len(payload["runs"][0]["results"]) > 0


def test_cli_scan_unparseable_format_sarif(tmp_path: Path) -> None:
    root = tmp_path / "project"
    import shutil

    shutil.copytree(UNPARSEABLE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    res = runner.invoke(app, ["scan", str(root), "--format", "sarif"])
    payload = json.loads(res.stdout)
    assert payload["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert len(payload["runs"][0]["invocations"][0]["toolExecutionNotifications"]) > 0
