"""Terminal rendering of findings.

The evidence path is the product. A severity label and a line number is what
every other scanner already prints.
"""

from rich.console import Console

from .models import Coverage, Finding

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_ROLE_LABEL = {
    "entry": "entry",
    "source": "source",
    "propagator": "flows",
    "model": "model",
    "sink": "sink",
    "binding": "binding",
    "policy": "policy",
    "gap": "gap",
}

# How many broken constructs the coverage block names before it starts counting
# instead. A project with four hundred parse failures has a systemic problem -
# the wrong PHP version, a vendored directory that should have been excluded -
# and printing four hundred lines above the findings buries the findings without
# telling the reader anything the first few and a total did not. Matches the cap
# cli.py already uses for the unparsed-file list.
_FAILURES_SHOWN = 5


def render_coverage(coverage: Coverage, console: Console) -> None:
    """Print how much of the project the scan understood.

    Printed on every scan, complete or not, and printed before the findings.
    docs/16-reporting puts coverage second in every format, ahead of the
    findings, for the reason invariant 4 gives: a report claiming a clean result
    has to show what it actually managed to look at. Printing it only when it is
    imperfect would teach readers that silence means 100%, and silence is
    exactly what a 40%-blind scan produces too.

    Both rates are formatted to one decimal place. That is a deterministic
    rendering of the ratio (invariant 8) rather than the platform's float repr,
    and the counts either side of it are the exact values the rate came from.

    A second line names the constructs that failed to parse, when any are
    recorded. Per-construct detail is only worth collecting if somebody sees it:
    "2/3 files parsed" tells a reader a gap exists, "method
    ReportController::index" tells them where to look. It is capped rather than
    complete, because a coverage block that can be hundreds of lines long is one
    a reader learns to scroll past, and the number not shown is stated so the
    cap cannot read as the total.
    """
    perfect = coverage.parse_success_rate == 1.0 and coverage.call_resolution_rate == 1.0
    style = "dim" if perfect else "yellow"
    console.print()
    console.print(
        f"[{style}]Coverage: "
        f"{coverage.files_parsed}/{coverage.files_discovered} files parsed "
        f"({coverage.parse_success_rate:.1%}), "
        f"{coverage.calls_resolved}/{coverage.calls_attempted} call sites resolved "
        f"({coverage.call_resolution_rate:.1%})[/{style}]"
    )

    if coverage.parse_failures:
        shown = "; ".join(f.label for f in coverage.parse_failures[:_FAILURES_SHOWN])
        hidden = len(coverage.parse_failures) - _FAILURES_SHOWN
        more = f" and {hidden} more" if hidden > 0 else ""
        console.print(f"[{style}]Parse errors in: {shown}{more}[/{style}]")


def render(findings: list[Finding], console: Console) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity, "white")
        review_tag = " (Needs Review)" if finding.needs_review else ""
        console.print()
        console.print(
            f"[{style}]{finding.severity.upper()}[/{style}]{review_tag} - {finding.title}"
        )
        console.print(
            f"  [dim]{finding.span.file}:{finding.span.start_line} · "
            f"{' '.join(finding.cwe)} · {finding.rule_id}[/dim]"
        )
        console.print()

        for number, step in enumerate(finding.evidence_path, start=1):
            label = _ROLE_LABEL.get(step.role, step.role)
            console.print(
                f"  [dim]{number}.[/dim] {step.span.file.name}:{step.span.start_line}"
                f"  [bold]{label}[/bold]"
            )
            console.print(f"     [white]{step.snippet}[/white]")
            if step.note:
                console.print(f"     [dim]{step.note}[/dim]")

        console.print()
        if finding.alternative_paths:
            count = len(finding.alternative_paths)
            plural = "s" if count != 1 else ""
            console.print(f"  [dim]+ {count} alternative path{plural} reached this sink[/dim]")
            console.print()
        console.print(f"  [bold]Fix:[/bold] {finding.remediation}")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
    plural = "s" if len(findings) != 1 else ""
    console.print()
    console.print(f"[bold]{len(findings)} finding{plural}[/bold] ({breakdown})")
