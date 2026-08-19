"""The document every format renders is sorted before any format sees it."""

from pathlib import Path

from vigilloo.models import Coverage, Finding, PathStep, Span
from vigilloo.report.document import SCHEMA_VERSION, build_document


def _finding(rule_id: str, severity: str, file: str, line: int) -> Finding:
    span = Span(file=Path(file), start_line=line, start_col=0, end_line=line, end_col=9)
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=f"{rule_id} in {file}",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep(role="sink", span=span, snippet="q($x)"),),
    )


def _coverage() -> Coverage:
    return Coverage(
        files_discovered=10,
        files_unreadable=0,
        files_with_errors=1,
        calls_resolved=8,
        calls_unresolved=2,
    )


def test_findings_sort_by_severity_then_rule_then_path_then_line() -> None:
    """docs/16-reporting fixes this order. Input order must not survive.

    scan_project's output order is an implementation detail of the rule
    dispatch; if it ever changes, two scans of unchanged code would diff
    against each other and Task 9's precision harness would report churn
    that is not a detection change.
    """
    unsorted = [
        _finding("php.xss", "low", "b.php", 5),
        _finding("php.xss", "critical", "b.php", 5),
        _finding("php.xss", "critical", "a.php", 99),
        _finding("laravel.raw-query", "critical", "b.php", 5),
        _finding("php.xss", "critical", "b.php", 2),
    ]

    doc = build_document(unsorted, _coverage(), engine_version="0.1.0", ruleset_hash="abc")

    assert [(f.rule_id, f.severity, str(f.span.file), f.span.start_line) for f in doc.findings] == [
        ("laravel.raw-query", "critical", "b.php", 5),
        ("php.xss", "critical", "a.php", 99),
        ("php.xss", "critical", "b.php", 2),
        ("php.xss", "critical", "b.php", 5),
        ("php.xss", "low", "b.php", 5),
    ]


def test_severity_counts_only_names_severities_present() -> None:
    """A zero is not reported as a key.

    An absent severity and a severity with zero findings are the same fact,
    and emitting both shapes lets a consumer write a check that passes on one
    scan and fails on the next for no reason.
    """
    doc = build_document(
        [_finding("php.xss", "critical", "a.php", 1), _finding("php.xss", "low", "b.php", 1)],
        _coverage(),
        engine_version="0.1.0",
        ruleset_hash="abc",
    )
    assert doc.severity_counts == {"critical": 1, "low": 1}


def test_metadata_carries_no_timestamp() -> None:
    """Invariant 8. A duration or a wall clock in the document is a byte that
    changes between two identical scans, so neither is allowed to enter it.
    """
    doc = build_document([], _coverage(), engine_version="0.1.0", ruleset_hash="abc")
    assert doc.metadata.engine_version == "0.1.0"
    assert doc.metadata.ruleset_hash == "abc"
    assert doc.metadata.schema_version == SCHEMA_VERSION
    assert not hasattr(doc.metadata, "duration_ms")
    assert not hasattr(doc.metadata, "timestamp")
