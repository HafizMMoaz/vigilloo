"""Command line interface for Vigilloo."""

import sqlite3
import time
from pathlib import Path

import typer
from rich.console import Console

from . import __version__, store
from .graph import coverage, load_project
from .models import WalkStats
from .report import render, render_coverage
from .rules import RULESET_HASH, scan_project
from .workspace import Workspace
from .workspace.migrations import SchemaTooNewError

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

    # The graph still takes a bare root because it holds nothing across runs. The store is
    # what writes under workspace.dir, and it is handed the finished Project below.
    started = time.perf_counter()
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

    # A refused autoload mapping is a whole namespace that no longer resolves, which is a
    # larger blind spot than any single unparsed file and exactly the kind invariant 4
    # forbids hiding. It prints here, with the other caveats and ahead of the findings,
    # rather than raising: one crafted or malformed entry degrades the scan, it does not
    # end it. See vigilloo.laravel.detect for why skipping is the chosen answer.
    for message in project.autoload.rejected:
        console.print(f"[yellow]Autoload mapping ignored: {message}.[/yellow]")

    if project.files and not project.routes:
        console.print(
            "[yellow]No HTTP entry points discovered; route-reachable findings "
            "cannot be reported.[/yellow]"
        )

    findings = scan_project(project, stats)

    # Coverage is measured only once the analysis has run, because the walk is
    # what discovers the call sites, but it is printed ahead of the findings:
    # docs/16-reporting puts it second in every format, before them, so a clean
    # result can never be read without the size of the blind spot beside it.
    render_coverage(coverage(project, stats), console)
    render(findings, console)

    # The findings are already correct and already on screen; the store is history for the next
    # run, not this run's result, so a full disk or an unwritable database must not turn a good
    # scan into a failed command. Silence is the other wrong answer: a lost scan is a hole in
    # the history that baselines and `report --compare` read later, and invariant 4 says
    # coverage is reported, never hidden. So it warns, and the exit code stays the findings'.
    # This covers the write, not Workspace.open above: a root where .vigilloo/ cannot even be
    # created is a scan that never started, and it still fails loudly at the top.
    try:
        conn = store.connect(workspace)
        try:
            store.record_scan(
                conn,
                project,
                findings,
                engine_version=__version__,
                ruleset_hash=RULESET_HASH,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        finally:
            conn.close()
    except SchemaTooNewError as exc:
        # Not a warning, unlike everything below it. A full disk is this run's bad luck and the
        # next run may well succeed; a workspace written by a newer build will refuse this one
        # every time, and every scan from here on would silently record nothing. docs/19-cli
        # gives 4 to a configuration error, which is what this is: the workspace is intact and
        # the tool pointed at it is the wrong version. The exit code overrides the findings'
        # own, because "you are running the wrong build" outranks how many findings that build
        # managed to produce.
        typer.secho(f"Error: {exc}", err=True, fg="red")
        raise typer.Exit(4) from exc
    except (sqlite3.Error, OSError) as exc:
        console.print(f"[yellow]Scan history not recorded: {exc}[/yellow]")

    raise typer.Exit(1 if findings else 0)
