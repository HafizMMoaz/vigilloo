from pathlib import Path

from vigilloo.models import Finding, PathStep, Span


def _span(line: int) -> Span:
    return Span(Path("a.php"), line, 0, line, 10)


def test_finding_requires_evidence_path() -> None:
    """A finding without a path is a bug, not a finding."""
    try:
        Finding(
            rule_id="php.sql-injection",
            severity="critical",
            title="SQL Injection",
            cwe=("CWE-89",),
            span=_span(42),
            evidence_path=(),
        )
    except ValueError as exc:
        assert "evidence path" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError for empty evidence path")


def test_fingerprint_is_stable_across_line_moves() -> None:
    """Fingerprints must survive reformatting so baselines keep working."""
    steps_a = (PathStep("source", _span(10), "$r->input('s')", ""),
               PathStep("sink", _span(42), "orderByRaw", ""))
    steps_b = (PathStep("source", _span(30), "$r->input('s')", ""),
               PathStep("sink", _span(62), "orderByRaw", ""))
    a = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(42), steps_a)
    b = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(62), steps_b)
    assert a.fingerprint == b.fingerprint
    assert a.id != b.id
