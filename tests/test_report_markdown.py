"""Markdown renders the same document the JSON does."""

from pathlib import Path

from vigilloo.models import Coverage, Finding, PathStep, Span
from vigilloo.report.document import ReportDocument, build_document
from vigilloo.report.markdown import render_markdown


def _document(findings: list[Finding]) -> ReportDocument:
    coverage = Coverage(
        files_discovered=4,
        files_unreadable=0,
        files_with_errors=1,
        calls_resolved=3,
        calls_unresolved=1,
    )
    return build_document(findings, coverage, engine_version="0.1.0", ruleset_hash="abc")


def _finding() -> Finding:
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    return Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(role="source", span=span, snippet="$r->input('q')", note="request"),
            PathStep(role="sink", span=span, snippet="whereRaw($q)"),
        ),
        remediation="Bind the parameter.",
    )


def test_coverage_precedes_the_findings() -> None:
    """docs/16-reporting puts coverage second in every format, ahead of the
    findings, so a clean result can never be read without the size of the
    blind spot beside it.
    """
    out = render_markdown(_document([_finding()]))
    assert out.index("## Coverage") < out.index("## Findings")


def test_every_evidence_step_is_numbered_in_order() -> None:
    """Invariant 2. The path is the product; a Markdown report that dropped
    it would be the line-number-and-severity output every other scanner
    already produces.
    """
    out = render_markdown(_document([_finding()]))
    assert "1. `app/X.php:4`" in out
    assert "2. `app/X.php:4`" in out
    assert "$r->input('q')" in out
    assert "whereRaw($q)" in out


def test_clean_scan_still_reports_coverage() -> None:
    """Invariant 4. No findings is not the same as nothing to say."""
    out = render_markdown(_document([]))
    assert "## Coverage" in out
    assert "No findings" in out
