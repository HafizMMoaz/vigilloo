"""Terminal rendering of findings.

The evidence path is the product. A severity label and a line number is what
every other scanner already prints.
"""

from rich.console import Console

from .models import Finding

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
}


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
