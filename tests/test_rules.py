from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_produces_one_critical_sql_injection_finding() -> None:
    findings = scan_project(load_project(FIXTURE))
    assert len(findings) == 1

    finding = findings[0]
    assert finding.rule_id == "php.sql-injection"
    assert finding.severity == "critical"
    assert finding.cwe == ("CWE-89",)
    assert finding.span.file.name == "OrderRepository.php"
    assert len(finding.evidence_path) == 4
    assert finding.remediation


def test_findings_are_stable_across_runs() -> None:
    a = scan_project(load_project(FIXTURE))
    b = scan_project(load_project(FIXTURE))
    assert [f.id for f in a] == [f.id for f in b]
    assert [f.fingerprint for f in a] == [f.fingerprint for f in b]


def test_fingerprint_is_independent_of_how_the_root_was_spelled() -> None:
    """A relative and an absolute scan of the same code must share a baseline."""
    relative = scan_project(load_project(FIXTURE))
    absolute = scan_project(load_project(FIXTURE.resolve()))
    assert [f.fingerprint for f in relative] == [f.fingerprint for f in absolute]
