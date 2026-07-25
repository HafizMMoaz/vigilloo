"""Command line interface for Vigilloo."""

from pathlib import Path

import typer
from rich.console import Console

from vigilloo import __version__
from vigilloo.graph import load_project
from vigilloo.report import render
from vigilloo.rules import scan_project

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

    project = load_project(path)

    if not project.files and not project.failed:
        console.print(f"[yellow]No PHP files found under {path}.[/yellow]")
        raise typer.Exit(0)

    if project.failed:
        console.print(
            f"[yellow]{len(project.failed)} file(s) could not be read.[/yellow]"
        )

    findings = scan_project(project)
    render(findings, console)
    raise typer.Exit(1 if findings else 0)
