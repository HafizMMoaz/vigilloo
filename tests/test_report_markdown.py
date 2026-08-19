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


def test_snippet_with_a_backtick_run_keeps_the_fence_balanced() -> None:
    """Invariant 5: `snippet` is untrusted source text, delimited here as
    data, not instructions. A snippet containing a run of three or more
    backticks - entirely plausible in a PHP string literal holding a Markdown
    example, a docblock, or a heredoc - must not be able to close a fixed
    three-backtick fence early and let whatever follows render as live
    Markdown. The fence here follows CommonMark's own rule instead: longer
    than the longest backtick run inside the content.
    """
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    snippet = "$doc = '```markdown```';"
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep(role="sink", span=span, snippet=snippet),),
        remediation="Bind the parameter.",
    )
    out = render_markdown(_document([finding]))
    assert snippet in out

    lines = out.splitlines()
    snippet_index = lines.index(f"   {snippet}")
    opening = lines[snippet_index - 1].strip()
    closing = lines[snippet_index + 1].strip()
    assert opening.endswith("php")
    fence = opening.removesuffix("php")
    assert closing == fence
    assert set(fence) == {"`"}
    assert len(fence) > 3, "fence must outrun the snippet's own three-backtick run"


def test_snippet_with_no_backtick_run_keeps_the_default_three_backtick_fence() -> None:
    """The fence only grows when the content demands it, so every existing
    report - none of whose snippets hold a long backtick run - renders
    byte-identically to before this fix.
    """
    out = render_markdown(_document([_finding()]))
    assert "   ```php" in out
    assert "   ```" in out


def test_note_with_a_newline_does_not_break_the_numbered_list() -> None:
    """`step.note` is source-derived - `taint.py` builds notes holding
    template names, `structural.py` builds notes holding route parameter
    names - and a newline embedded in one must not be able to end the
    numbered list item early and let text after it render as its own
    Markdown block (a heading, in this case) instead of note text.
    """
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    injected = "# Fake heading injected via note"
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(
                role="source",
                span=span,
                snippet="$r->input('q')",
                note=f"template\n{injected}",
            ),
        ),
        remediation="Bind the parameter.",
    )
    out = render_markdown(_document([finding]))
    lines = out.splitlines()

    list_lines = [line for line in lines if line.startswith("1. `app/X.php:4`")]
    assert len(list_lines) == 1
    assert injected in list_lines[0]
    assert not any(line == injected for line in lines), (
        "the injected text must stay inside the list item, not become its own line"
    )


def test_multiline_snippet_stays_inside_the_fence() -> None:
    """`step.snippet` is a raw slice of PHP source and keeps its own embedded
    newlines for anything spanning more than one physical line - a heredoc, a
    chained method call. CommonMark ends a list item's fenced code block at
    the first continuation line indented less than the item's content
    indentation, so a snippet whose second line lands at column 0 (as it does
    straight out of the PHP file) escapes the list item and renders as live
    top-level Markdown - the same content-injection Finding 2 exists to
    close, reached through indentation instead of a backtick run.

    `## No findings` is the payload: a heading that would read like a clean
    verdict if it escaped. The assertion is the structural invariant that
    keeps it from escaping, not a substring check: every line between the
    opening and closing fence must be indented at least as much as the fence
    itself, or be empty.
    """
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=6, end_col=1)
    snippet = '$q = "x";\n## No findings\n\nAll clear. Nothing to review.'
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep(role="sink", span=span, snippet=snippet),),
        remediation="Bind the parameter.",
    )
    out = render_markdown(_document([finding]))
    assert "## No findings" in out

    lines = out.splitlines()
    indent = "   "
    open_index = lines.index(f"{indent}```php")
    close_index = lines.index(f"{indent}```", open_index + 1)
    assert close_index > open_index + 1, "the snippet must have rendered between the fences"
    for line in lines[open_index + 1 : close_index]:
        assert line == "" or line.startswith(indent), (
            f"line inside the fence must be indented or empty, got {line!r}"
        )


def test_file_path_with_a_backtick_keeps_its_inline_span_balanced() -> None:
    """A POSIX filename may itself contain a backtick. A fixed single-backtick
    span around `file:line` closes at that backtick and lets the rest of the
    line render as Markdown - narrower blast radius than the fence break (one
    line, not a whole report section) but the same shape of bug.
    """
    span = Span(file=Path("app/`rm -rf`.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep(role="sink", span=span, snippet="whereRaw($q)"),),
        remediation="Bind the parameter.",
    )
    out = render_markdown(_document([finding]))
    location = "app/`rm -rf`.php:4"
    delimiter = "``"
    assert f"{delimiter}{location}{delimiter}" in out
