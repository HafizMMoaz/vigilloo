"""Implementation of the `vigilloo explain` command.

Provides detailed, step-by-step explanation of a finding's evidence path,
including CWE context, source-to-sink flow, and remediation guidance.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import store
from .graph import load_project
from .models import Finding, WalkStats
from .rules import scan_project
from .workspace import Workspace


@dataclass
class ExplainableFinding:
    id: str
    fingerprint: str
    rule_id: str
    severity: str
    title: str
    file: str
    line: int
    cwe: list[str]
    remediation: str
    steps: list[tuple[str, str, int, str, str]]  # role, file, line, snippet, note
    first_seen_scan: int | None = None


def _from_stored_finding(sf: store.StoredFinding) -> ExplainableFinding:
    steps: list[tuple[str, str, int, str, str]] = []
    for step in sf.path:
        file_str = str(step.file) if step.file else ""
        line_num = step.line if step.line is not None else 0
        steps.append((step.role, file_str, line_num, step.snippet, step.note))

    return ExplainableFinding(
        id=sf.id,
        fingerprint=sf.fingerprint,
        rule_id=sf.rule_id,
        severity=sf.severity,
        title=sf.title,
        file=str(sf.file) if sf.file else "",
        line=sf.start_line if sf.start_line is not None else 0,
        cwe=list(sf.cwe),
        remediation=sf.remediation,
        steps=steps,
        first_seen_scan=sf.first_seen_scan,
    )


def _from_live_finding(f: Finding) -> ExplainableFinding:
    steps: list[tuple[str, str, int, str, str]] = []
    for step in f.evidence_path:
        file_str = str(step.span.file)
        line_num = step.span.start_line
        steps.append((step.role, file_str, line_num, step.snippet, ""))

    return ExplainableFinding(
        id=f.id,
        fingerprint=f.fingerprint,
        rule_id=f.rule_id,
        severity=f.severity,
        title=f.title,
        file=str(f.span.file),
        line=f.span.start_line,
        cwe=list(f.cwe),
        remediation=f.remediation,
        steps=steps,
    )


def _lookup_in_database(root: Path, target: str, cwe: str | None) -> list[ExplainableFinding]:
    db_path = root / ".vigilloo" / "vigilloo.db"
    if not db_path.is_file():
        return []

    results: list[ExplainableFinding] = []
    try:
        conn = sqlite3.connect(db_path)
        try:
            pid = store.project_id_for(conn, root)
            if pid is None:
                return []
            latest_id = store.latest_scan(conn, pid)
            if latest_id is None:
                return []
            findings = store.findings_for_scan(conn, latest_id)
            for f in findings:
                if cwe and cwe not in f.cwe and not any(c.endswith(cwe) for c in f.cwe):
                    continue
                if target:
                    if (
                        target in f.fingerprint
                        or target in f.id
                        or target == f.rule_id
                        or target.lower() in f.title.lower()
                    ):
                        results.append(_from_stored_finding(f))
                elif cwe:
                    results.append(_from_stored_finding(f))
        finally:
            conn.close()
    except Exception:
        pass
    return results


def _lookup_live(root: Path, target: str, cwe: str | None) -> list[ExplainableFinding]:
    workspace = Workspace.open(root)
    stats = WalkStats()
    project = load_project(workspace.root, stats)
    findings = scan_project(project, stats)

    results: list[ExplainableFinding] = []
    for f in findings:
        if cwe and cwe not in f.cwe and not any(c.endswith(cwe) for c in f.cwe):
            continue
        if target:
            if (
                target in f.fingerprint
                or target in f.id
                or target == f.rule_id
                or target.lower() in f.title.lower()
            ):
                results.append(_from_live_finding(f))
        elif cwe:
            results.append(_from_live_finding(f))
    return results


def run_explain(
    target: str,
    path: Path,
    cwe: str | None = None,
    console: Console | None = None,
) -> int:
    """Explain one or more findings matching target or CWE."""
    if console is None:
        console = Console()

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    # Try fast database lookup first
    findings = _lookup_in_database(resolved_path, target, cwe)
    if not findings:
        # Fallback to live scan
        findings = _lookup_live(resolved_path, target, cwe)

    if not findings:
        query_desc = f"'{target}'" if target else f"CWE {cwe}"
        console.print(f"[yellow]No findings matching {query_desc} found in {path}.[/yellow]")
        return 1

    for f in findings:
        _render_explanation(f, console)

    return 0


def _render_explanation(f: ExplainableFinding, console: Console) -> None:
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    sev_style = severity_colors.get(f.severity.lower(), "white")

    header_text = Text()
    header_text.append(f"{f.severity.upper()} ", style=sev_style)
    header_text.append(f"- {f.title}\n", style="bold")
    header_text.append(f"Rule: {f.rule_id}", style="cyan")
    if f.cwe:
        header_text.append(f" · CWE: {', '.join(f.cwe)}", style="magenta")
    header_text.append(f"\nLocation: {f.file}:{f.line}")
    header_text.append(f"\nFingerprint: {f.fingerprint} (ID: {f.id})", style="dim")
    if f.first_seen_scan is not None:
        header_text.append(f"\nFirst recorded in scan #{f.first_seen_scan}", style="dim")

    console.print()
    console.print(Panel(header_text, title="[bold]Finding Summary[/bold]", expand=False))

    console.print("\n[bold]Evidence Path (step-by-step):[/bold]")
    for i, (role, file_path, line, snippet, note) in enumerate(f.steps, 1):
        role_badge = f"[{role.upper()}]"
        if role == "source":
            badge_styled = f"[cyan]{role_badge}[/cyan]"
        elif role == "sink":
            badge_styled = f"[red]{role_badge}[/red]"
        elif role == "transform":
            badge_styled = f"[yellow]{role_badge}[/yellow]"
        else:
            badge_styled = f"[magenta]{role_badge}[/magenta]"

        console.print(f"  {i}. {badge_styled} [bold]{file_path}:{line}[/bold]")
        if snippet:
            # Print indented code snippet
            for snippet_line in snippet.strip().splitlines():
                console.print(f"     [dim]│[/dim] {snippet_line}")
        if note:
            console.print(f"     [italic dim]Note: {note}[/italic dim]")
        console.print()

    if f.remediation:
        remedy_panel = Panel(
            Text(f.remediation, style="green"),
            title="[bold green]Remediation Guidance[/bold green]",
            expand=False,
        )
        console.print(remedy_panel)
    console.print()
