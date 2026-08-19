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


def _finding_section(finding: Finding) -> list[str]:
    mark = _SEVERITY_MARK.get(finding.severity, "⚪")
    review = " (Needs Review)" if finding.needs_review else ""
    lines = [
        f"### {mark} {finding.severity.title()} - {finding.title}{review}",
        "",
        f"`{finding.span.file.as_posix()}:{finding.span.start_line}` · "
        f"{' '.join(finding.cwe)} · `{finding.rule_id}`",
        "",
        "**Evidence path**",
        "",
    ]
    for number, step in enumerate(finding.evidence_path, start=1):
        note = f" - {step.note}" if step.note else ""
        lines.append(
            f"{number}. `{step.span.file.as_posix()}:{step.span.start_line}` - {step.role}{note}"
        )
        lines.append("")
        lines.append("   ```php")
        lines.append(f"   {step.snippet}")
        lines.append("   ```")
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
