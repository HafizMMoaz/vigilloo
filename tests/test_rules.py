from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_produces_the_sql_injection_and_xss_findings() -> None:
    findings = scan_project(load_project(FIXTURE))
    by_rule = {f.rule_id for f in findings}
    assert by_rule == {"php.sql-injection", "php.xss", "laravel.mass-assignment"}

    finding = next(f for f in findings if f.rule_id == "php.sql-injection")
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
