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


def render(findings: list[Finding], console: Console) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    for finding in findings:
        style = _SEVERITY_STYLE.get(finding.severity, "white")
        console.print()
        console.print(f"[{style}]{finding.severity.upper()}[/{style}] - {finding.title}")
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
        console.print(f"  [bold]Fix:[/bold] {finding.remediation}")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
    plural = "s" if len(findings) != 1 else ""
    console.print()
    console.print(f"[bold]{len(findings)} finding{plural}[/bold] ({breakdown})")
