"""Command line interface for Vigilloo."""

from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .graph import load_project
from .models import WalkStats
from .report import render
from .rules import scan_project
from .workspace import Workspace

app = typer.Typer(
    name="vigilloo",
    help="AI-native application security platform.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vigilloo {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Vigilloo command line interface."""


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Project root to scan."),  # noqa: B008
) -> None:
    """Scan a Laravel project for security findings."""
    console = Console()

    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", err=True, fg="red")
        raise typer.Exit(2)
    if not path.is_dir():
        typer.secho(f"Error: not a directory: {path}", err=True, fg="red")
        raise typer.Exit(2)

    # The graph still takes a bare root because it holds nothing across runs. It takes
    # the workspace itself once it writes to the store that lives under workspace.dir.
    workspace = Workspace.open(path)
    stats = WalkStats()
    project = load_project(workspace.root, stats)

    if not project.files and not project.failed:
        console.print(f"[yellow]No PHP files found under {path}.[/yellow]")
        raise typer.Exit(0)

    if project.failed:
        console.print(f"[yellow]{len(project.failed)} file(s) could not be read.[/yellow]")

    # Coverage caveats are printed before any finding, so a clean report can
    # never appear on screen without whatever gap produced it also on screen.
    if project.unparsed:
        shown = ", ".join(str(p) for p in project.unparsed[:5])
        more = f" and {len(project.unparsed) - 5} more" if len(project.unparsed) > 5 else ""
        console.print(
            f"[yellow]{len(project.unparsed)} file(s) had syntax errors and were only "
            f"partially analysed: {shown}{more}.[/yellow]"
        )

    if project.files and not project.routes:
        console.print(
            "[yellow]No HTTP entry points discovered; route-reachable findings "
            "cannot be reported.[/yellow]"
        )

    findings = scan_project(project, stats)

    if stats.unresolved:
        console.print(f"[yellow]{stats.unresolved} call site(s) could not be resolved.[/yellow]")

    render(findings, console)
    raise typer.Exit(1 if findings else 0)
