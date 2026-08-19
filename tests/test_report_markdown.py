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
    it, or numbered it out of order, would be asserting something false
    about how data flows from source to sink.

    The assertions are positional, not bare substring checks: each numbered
    line is matched together with its role, and the source line's position
    is compared against the sink line's position. A test that only checked
    "1. ..." and "2. ..." exist, and separately that "source" and "sink"
    appear somewhere, would still pass if the two steps were swapped - which
    is exactly the defect this test exists to catch.
    """
    out = render_markdown(_document([_finding()]))
    source_line = "1. `app/X.php:4` - source - request"
    sink_line = "2. `app/X.php:4` - sink"
    assert source_line in out
    assert sink_line in out
    assert out.index(source_line) < out.index(sink_line)
    assert "$r->input('q')" in out
    assert "whereRaw($q)" in out


def test_clean_scan_still_reports_coverage() -> None:
    """Invariant 4. No findings is not the same as nothing to say."""
    out = render_markdown(_document([]))
    assert "## Coverage" in out
    assert "No findings" in out


def test_needs_review_alternative_paths_and_remediation_render() -> None:
    """`_finding_section` renders three optional annotations beyond the
    evidence path: the needs-review tag, the alternative-path count and the
    remediation line. None of the other tests carries a finding that sets
    them, so nothing exercised this before.
    """
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(role="source", span=span, snippet="$r->input('q')", note="request"),
            PathStep(role="sink", span=span, snippet="whereRaw($q)"),
        ),
        alternative_paths=(
            (
                PathStep(role="source", span=span, snippet="$r->query('q')"),
                PathStep(role="sink", span=span, snippet="whereRaw($q)"),
            ),
        ),
        remediation="Bind the parameter.",
        needs_review=True,
    )
    out = render_markdown(_document([finding]))
    assert "(Needs Review)" in out
    assert "1 alternative path reached this sink." in out
    assert "**Fix** - Bind the parameter." in out
