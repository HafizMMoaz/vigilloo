"""Secret and credential scanning for working tree and git history."""

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .history import scan_git_history
from .patterns import SECRET_RULES, SecretRule
from .redact import redact_secret
from .scanner import SecretFinding, scan_working_tree


def scan_secrets(path: Path, history: bool = False) -> list[SecretFinding]:
    """Scan working tree or git history for secrets."""
    if history:
        return scan_git_history(path)
    return scan_working_tree(path)


def run_secrets(
    path: Path,
    history: bool = False,
    as_json: bool = False,
) -> int:
    """Execute the `vigilloo secrets` CLI workflow."""
    console = Console(stderr=True) if as_json else Console()

    if not path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    if history and not (path / ".git").exists():
        console.print(f"[red]Error: not a git repository: {path}[/red]")
        return 2

    findings = scan_secrets(path, history=history)

    if as_json:
        payload = {
            "path": str(path.resolve()),
            "history_mode": history,
            "secrets_count": len(findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "redacted_value": f.redacted_value,
                    "commit_hash": f.commit_hash,
                    "commit_author": f.commit_author,
                    "commit_date": f.commit_date,
                }
                for f in findings
            ],
        }
        print(json.dumps(payload, indent=2))  # noqa: T201
        return 1 if findings else 0

    mode_label = "Git history" if history else "Working tree"
    console.print(f"[bold cyan]Scanned {mode_label} for exposed secrets in {path}[/bold cyan]\n")

    if not findings:
        console.print("[bold green]No exposed secrets or credentials detected.[/bold green]")
        return 0

    table = Table(title="Exposed Secrets", title_justify="left", show_header=True)
    table.add_column("Rule", style="bold", no_wrap=True)
    table.add_column("Severity")
    table.add_column("File / Location", overflow="fold")
    if history:
        table.add_column("Commit", no_wrap=True)
    table.add_column("Masked Value", no_wrap=True)

    for f in findings:
        sev_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }.get(f.severity, "white")

        loc = f"{f.file_path}:{f.line_number}"
        row = [
            f.rule_name,
            f"[{sev_color}]{f.severity.upper()}[/{sev_color}]",
            loc,
        ]
        if history:
            short_commit = f.commit_hash[:8] if f.commit_hash else "unknown"
            row.append(short_commit)
        row.append(f.redacted_value)

        table.add_row(*row)

    console.print(table)
    suffix = "finding" if len(findings) == 1 else "findings"
    console.print(f"\n[bold red]Found {len(findings)} exposed secret {suffix}.[/bold red]")
    return 1


__all__ = [
    "SECRET_RULES",
    "SecretFinding",
    "SecretRule",
    "redact_secret",
    "run_secrets",
    "scan_git_history",
    "scan_secrets",
    "scan_working_tree",
]
