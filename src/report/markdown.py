"""Markdown for a PR comment, a ticket, or a human reading a file.

Renders the same `ReportDocument` the JSON does, so the report a reviewer
reads and the report CI gates on cannot describe different scans.

Deterministic for the same reason and by the same means: the document arrives
sorted, and nothing here consults a clock or the environment.
"""

from ..models import Finding
from .document import ReportDocument

_SEVERITY_MARK = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _longest_backtick_run(text: str) -> int:
    """The length of the longest run of consecutive backticks in `text`.

    Sizes a CommonMark delimiter so untrusted content cannot close it early:
    both `_fence` (a block delimiter) and `_inline_code` (a span delimiter)
    depend on it, each adding its own floor afterwards. One copy of this
    count is deliberate, not just tidiness - it is security-relevant logic,
    and a bug fixed in one copy but not a duplicate would silently leave the
    other delimiter closable again while its own tests kept passing.
    """
    longest = 0
    current = 0
    for char in text:
        if char == "`":
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _fence(snippet: str) -> str:
    """A backtick fence the snippet cannot close early.

    Invariant 5: `snippet` is untrusted source text pulled from the scanned
    project, delimited here as data, not instructions. A fixed three-backtick
    fence is not delimiting - a snippet containing a run of three or more
    backticks (a PHP docblock, a heredoc, a string literal holding a Markdown
    example) closes it early, and everything after renders as live Markdown
    wherever the report lands: a GitHub PR comment, a ticket.

    CommonMark's own answer is to make the fence longer than any backtick run
    the content contains, so it follows that rule: the fence is one backtick
    longer than the longest run in `snippet`, with three as the floor so
    ordinary snippets are unaffected. It is a pure function of the snippet
    content, so invariant 8 (byte-identical output for identical input) holds
    without extra care.
    """
    return "`" * max(3, _longest_backtick_run(snippet) + 1)


def _indented_lines(snippet: str, indent: str) -> list[str]:
    """Every physical line of `snippet`, indented to stay inside the list
    item's fenced code block.

    CommonMark requires every line of a fenced code block nested in a list
    item to stay at the item's content indentation; a continuation line
    indented less than that ends the list item, and the fence with it.
    `step.snippet` is a raw slice of PHP source (`node_text(...).strip()`)
    that keeps its own embedded newlines for anything spanning more than one
    physical line - a heredoc, a chained method call, any multi-statement
    construct - and indenting only the first line, as this module used to,
    left every continuation line at whatever column it had in the PHP file,
    often column 0. That is the same content-injection Finding 2 exists to
    close, just reached through indentation instead of a backtick run: the
    text after the escaped fence renders as live top-level Markdown.

    A blank line in the snippet becomes an empty string rather than an
    indented line of nothing, so a multi-line snippet with a blank line does
    not grow trailing whitespace `ruff format` and everyone else objects to.
    """
    normalized = snippet.replace("\r\n", "\n").replace("\r", "\n")
    return [f"{indent}{line}" if line else "" for line in normalized.split("\n")]


def _inline_code(content: str) -> str:
    """`content` wrapped in a backtick span it cannot close early.

    `finding.span.file` and `step.span.file` are paths under the scanned
    project, and a POSIX filename may itself contain a backtick - a fixed
    single-backtick span closes at the first one and lets the rest of that
    line render as Markdown. Same CommonMark rule as `_fence`, sized for an
    inline span: the delimiter is one backtick longer than the longest run in
    `content`, with a single backtick as the floor, which is what every
    existing report already renders and keeps rendering unchanged.
    """
    delimiter = "`" * max(1, _longest_backtick_run(content) + 1)
    return f"{delimiter}{content}{delimiter}"


def _single_line(text: str) -> str:
    """Collapse line breaks so a source-derived value cannot end a line early.

    `step.note` is source-derived in places - `taint.py` builds notes holding
    template names, `structural.py` builds notes holding route parameter
    names - and it is interpolated into one line of a numbered list. A
    newline in it would end that Markdown list item and let whatever follows
    the note render as fresh Markdown instead of the note text it was meant
    to be, which is the same content-injection shape as an unescaped code
    fence, just with a line break instead of a backtick run.
    """
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _finding_section(finding: Finding) -> list[str]:
    mark = _SEVERITY_MARK.get(finding.severity, "⚪")
    review = " (Needs Review)" if finding.needs_review else ""
    lines = [
        f"### {mark} {finding.severity.title()} - {finding.title}{review}",
        "",
        f"{_inline_code(f'{finding.span.file.as_posix()}:{finding.span.start_line}')} · "
        f"{' '.join(finding.cwe)} · `{finding.rule_id}`",
        "",
        "**Evidence path**",
        "",
    ]
    for number, step in enumerate(finding.evidence_path, start=1):
        note = f" - {_single_line(step.note)}" if step.note else ""
        location = _inline_code(f"{step.span.file.as_posix()}:{step.span.start_line}")
        lines.append(f"{number}. {location} - {step.role}{note}")
        lines.append("")
        fence = _fence(step.snippet)
        lines.append(f"   {fence}php")
        lines.extend(_indented_lines(step.snippet, "   "))
        lines.append(f"   {fence}")
        lines.append("")

    if finding.alternative_paths:
        count = len(finding.alternative_paths)
        plural = "s" if count != 1 else ""
        lines.append(f"*{count} alternative path{plural} reached this sink.*")
        lines.append("")

    if finding.remediation:
        lines.append(f"**Fix** - {finding.remediation}")
        lines.append("")
    return lines


def render_markdown(document: ReportDocument) -> str:
    """Serialise one scan as Markdown. Returns the text; printing is the
    caller's job, which is what keeps this module under the T20 lint rule.
    """
    coverage = document.coverage
    breakdown = ", ".join(f"{count} {sev}" for sev, count in document.severity_counts.items())
    lines = [
        "# Vigilloo scan",
        "",
        "## Summary",
        "",
        f"{len(document.findings)} finding(s)" + (f" ({breakdown})" if breakdown else ""),
        "",
        f"Engine `{document.metadata.engine_version}` · ruleset `{document.metadata.ruleset_hash}`",
        "",
        "## Coverage",
        "",
        f"- {coverage.files_parsed}/{coverage.files_discovered} files parsed "
        f"({coverage.parse_success_rate:.1%})",
        f"- {coverage.calls_resolved}/{coverage.calls_attempted} call sites resolved "
        f"({coverage.call_resolution_rate:.1%})",
        "",
    ]
    if coverage.parse_failures:
        lines.append("Parse errors in:")
        lines.append("")
        lines += [f"- {failure.label}" for failure in coverage.parse_failures]
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not document.findings:
        lines.append("No findings.")
        lines.append("")
    else:
        for finding in document.findings:
            lines += _finding_section(finding)

    return "\n".join(lines)
