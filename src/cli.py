"""Command line interface for Vigilloo."""

import json
import sqlite3
import time
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__, store
from .baseline import (
    DEFAULT_BASELINE_REL_PATH,
    diff_fingerprints,
    load_baseline_fingerprints,
    save_baseline_file,
)
from .doctor import run_doctor
from .explain import run_explain
from .graph import Project, coverage, load_project
from .graph_cli import run_graph_build, run_graph_export, run_graph_routes, run_graph_stats
from .init import run_init
from .models import Coverage, Finding, WalkStats
from .report import build_document, render, render_coverage, render_json, render_markdown
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


class OutputFormat(StrEnum):
    """The formats `scan` can emit.

    An Enum rather than a bare string so Typer rejects a typo with a usage
    error and lists the valid values. A misspelled --format that silently fell
    back to the terminal report would hand a pipeline output it cannot parse
    and no signal about why.
    """

    terminal = "terminal"
    json = "json"
    markdown = "markdown"


def _emit_report(
    findings: list[Finding],
    scan_coverage: Coverage,
    output_format: OutputFormat,
    machine: bool,
    console: Console,
) -> None:
    """Render findings and coverage in whichever format was asked for.

    The one place format dispatch happens, so the empty-project early exit
    below and the normal scan path at the end of `scan` cannot drift into two
    copies of the same if/else - a second copy is exactly the verbatim
    duplication a reviewer would flag, and the two paths disagreeing about
    what "json" means is worse than that.
    """
    if machine:
        # print() rather than console.print(): Rich would wrap the JSON at the
        # terminal width and interpret square brackets as markup, and a report
        # that changes shape with the width of the window is not a report a
        # pipeline can diff.
        document = build_document(
            findings, scan_coverage, engine_version=__version__, ruleset_hash=RULESET_HASH
        )
        if output_format is OutputFormat.json:
            print(render_json(document), end="")
        else:
            print(render_markdown(document), end="")
    else:
        render_coverage(scan_coverage, console)
        render(findings, console)


def _resolve_baseline_path(project_root: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    dot_vigilloo = project_root / DEFAULT_BASELINE_REL_PATH
    if dot_vigilloo.is_file():
        return dot_vigilloo
    root_baseline = project_root / "baseline.json"
    if root_baseline.is_file():
        return root_baseline
    return dot_vigilloo


def _load_latest_scan_fingerprints(path: Path) -> set[str] | None:
    db_path = path / ".vigilloo" / "vigilloo.db"
    if not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(db_path)
        try:
            pid = store.project_id_for(conn, path)
            if pid is None:
                return None
            ls_id = store.latest_scan(conn, pid)
            if ls_id is None:
                return None
            stored = store.findings_for_scan(conn, ls_id)
            return {f.fingerprint for f in stored}
        finally:
            conn.close()
    except Exception:
        return None


def _execute_scan(
    path: Path,
    console: Console,
    baseline_fingerprints: set[str] | None = None,
) -> tuple[Workspace, Project, WalkStats, list[Finding], Coverage]:
    workspace = Workspace.open(path)
    stats = WalkStats()
    project = load_project(workspace.root, stats)

    if not project.files and not project.failed:
        console.print(f"[yellow]No PHP files found under {path}.[/yellow]")
        return workspace, project, stats, [], coverage(project, stats)

    if project.failed:
        console.print(f"[yellow]{len(project.failed)} file(s) could not be read.[/yellow]")

    if project.unparsed:
        shown = ", ".join(str(p) for p in project.unparsed[:5])
        more = f" and {len(project.unparsed) - 5} more" if len(project.unparsed) > 5 else ""
        console.print(
            f"[yellow]{len(project.unparsed)} file(s) had syntax errors and were only "
            f"partially analysed: {shown}{more}.[/yellow]"
        )

    for message in project.autoload.rejected:
        console.print(f"[yellow]Autoload mapping ignored: {message}.[/yellow]")

    if project.files and not project.routes:
        console.print(
            "[yellow]No HTTP entry points discovered; route-reachable findings "
            "cannot be reported.[/yellow]"
        )

    findings = scan_project(project, stats, baseline=baseline_fingerprints)
    scan_coverage = coverage(project, stats)
    return workspace, project, stats, findings, scan_coverage


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Project root to scan."),  # noqa: B008
    baseline: Path | None = typer.Option(  # noqa: B008
        None,
        "--baseline",
        help="Suppress findings present in the baseline",
    ),
    output_format: OutputFormat = typer.Option(  # noqa: B008
        OutputFormat.terminal,
        "--format",
        help="Report format.",
    ),
) -> None:
    """Scan a Laravel project for security findings."""
    machine = output_format is not OutputFormat.terminal
    console = Console(stderr=True) if machine else Console()

    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", err=True, fg="red")
        raise typer.Exit(2)
    if not path.is_dir():
        typer.secho(f"Error: not a directory: {path}", err=True, fg="red")
        raise typer.Exit(2)

    baseline_fingerprints: set[str] | None = None
    if baseline is not None:
        if not baseline.exists():
            typer.secho(f"Error: baseline file does not exist: {baseline}", err=True, fg="red")
            raise typer.Exit(2)
        try:
            with baseline.open() as f:
                data = json.load(f)
                if isinstance(data, list):
                    if all(isinstance(x, str) for x in data):
                        baseline_fingerprints = set(data)
                    elif all(isinstance(x, dict) and "fingerprint" in x for x in data):
                        baseline_fingerprints = {x["fingerprint"] for x in data}
                    else:
                        typer.secho("Error: baseline file format invalid", err=True, fg="red")
                        raise typer.Exit(2)
                else:
                    typer.secho("Error: baseline file must contain a list", err=True, fg="red")
                    raise typer.Exit(2)
        except json.JSONDecodeError:
            typer.secho("Error: baseline file is not valid JSON", err=True, fg="red")
            raise typer.Exit(2) from None

    started = time.perf_counter()
    workspace, project, stats, findings, scan_coverage = _execute_scan(
        path, console, baseline_fingerprints=baseline_fingerprints
    )

    if not project.files and not project.failed:
        if machine:
            _emit_report([], scan_coverage, output_format, machine, console)
        raise typer.Exit(0)

    _emit_report(findings, scan_coverage, output_format, machine, console)

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
        typer.secho(f"Error: {exc}", err=True, fg="red")
        raise typer.Exit(4) from exc
    except (sqlite3.Error, OSError) as exc:
        console.print(f"[yellow]Scan history not recorded: {exc}[/yellow]")

    raise typer.Exit(1 if findings else 0)


@app.command()
def review(
    path: Path = typer.Argument(Path("."), help="Project root to review."),  # noqa: B008
    baseline: Path | None = typer.Option(  # noqa: B008
        None,
        "--baseline",
        help="Baseline file to compare against (defaults to .vigilloo/baseline.json).",
    ),
    output_format: OutputFormat = typer.Option(  # noqa: B008
        OutputFormat.terminal,
        "--format",
        help="Report format.",
    ),
) -> None:
    """Review new findings against baseline or previous scan."""
    machine = output_format is not OutputFormat.terminal
    console = Console(stderr=True) if machine else Console()

    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", err=True, fg="red")
        raise typer.Exit(2)
    if not path.is_dir():
        typer.secho(f"Error: not a directory: {path}", err=True, fg="red")
        raise typer.Exit(2)

    base_fingerprints: set[str] | None = None
    target_file = _resolve_baseline_path(path, baseline)
    if target_file.exists():
        try:
            base_fingerprints = load_baseline_fingerprints(target_file)
        except Exception as exc:
            typer.secho(f"Error reading baseline: {exc}", err=True, fg="red")
            raise typer.Exit(2) from exc
    elif baseline is not None:
        typer.secho(f"Error: baseline file does not exist: {baseline}", err=True, fg="red")
        raise typer.Exit(2)
    else:
        base_fingerprints = _load_latest_scan_fingerprints(path)

    _, project, _, findings, scan_coverage = _execute_scan(
        path, console, baseline_fingerprints=base_fingerprints
    )

    if base_fingerprints is not None:
        findings = [f for f in findings if f.fingerprint not in base_fingerprints]

    if not project.files and not project.failed:
        if machine:
            _emit_report([], scan_coverage, output_format, machine, console)
        raise typer.Exit(0)

    if not machine and not findings:
        console.print("[bold green]Review clean: no new findings introduced.[/bold green]")
        raise typer.Exit(0)

    _emit_report(findings, scan_coverage, output_format, machine, console)
    raise typer.Exit(1 if findings else 0)


baseline_app = typer.Typer(
    name="baseline",
    help="Manage baseline findings to suppress known issues.",
    no_args_is_help=True,
)
app.add_typer(baseline_app, name="baseline")


@baseline_app.command("create")
def baseline_create(
    path: Path = typer.Argument(Path("."), help="Project root to baseline."),  # noqa: B008
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "-o",
        "--output",
        help="Custom baseline file path (defaults to .vigilloo/baseline.json).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing baseline file.",
    ),
) -> None:
    """Accept current findings and write them to a baseline file."""
    console = Console()
    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", err=True, fg="red")
        raise typer.Exit(2)
    if not path.is_dir():
        typer.secho(f"Error: not a directory: {path}", err=True, fg="red")
        raise typer.Exit(2)

    target_file = output if output is not None else (path / DEFAULT_BASELINE_REL_PATH)
    if target_file.exists() and not force:
        console.print(
            f"[yellow]Baseline already exists at {target_file}. Use --force or "
            "'vigilloo baseline update'.[/yellow]"
        )
        raise typer.Exit(1)

    _, _, _, findings, _ = _execute_scan(path, console)
    save_baseline_file(target_file, findings)
    console.print(
        f"[bold green]✓ Created baseline with {len(findings)} finding(s) "
        f"at {target_file}[/bold green]"
    )
    raise typer.Exit(0)


@baseline_app.command("update")
def baseline_update(
    path: Path = typer.Argument(Path("."), help="Project root to baseline."),  # noqa: B008
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "-o",
        "--output",
        help="Baseline file path (defaults to existing baseline or .vigilloo/baseline.json).",
    ),
) -> None:
    """Update baseline with current findings."""
    console = Console()
    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", err=True, fg="red")
        raise typer.Exit(2)
    if not path.is_dir():
        typer.secho(f"Error: not a directory: {path}", err=True, fg="red")
        raise typer.Exit(2)

    target_file = _resolve_baseline_path(path, output)
    old_fingerprints: set[str] = set()
    if target_file.exists():
        try:
            old_fingerprints = load_baseline_fingerprints(target_file)
        except Exception as exc:
            typer.secho(f"Error reading existing baseline: {exc}", err=True, fg="red")
            raise typer.Exit(2) from exc

    _, _, _, findings, _ = _execute_scan(path, console)
    current_fps = [f.fingerprint for f in findings]
    diff = diff_fingerprints(current_fps, old_fingerprints)

    save_baseline_file(target_file, findings)
    console.print(
        f"[bold green]✓ Baseline updated at {target_file} ({len(findings)} total findings: "
        f"+{len(diff.added)} added, -{len(diff.removed)} removed, "
        f"{len(diff.unchanged)} unchanged)[/bold green]"
    )
    raise typer.Exit(0)


@baseline_app.command("diff")
def baseline_diff(
    path: Path = typer.Argument(Path("."), help="Project root to compare."),  # noqa: B008
    baseline: Path | None = typer.Option(  # noqa: B008
        None,
        "--baseline",
        help="Baseline file path (defaults to .vigilloo/baseline.json).",
    ),
) -> None:
    """Show differences between current findings and the baseline."""
    console = Console()
    if not path.exists():
        typer.secho(f"Error: path does not exist: {path}", err=True, fg="red")
        raise typer.Exit(2)
    if not path.is_dir():
        typer.secho(f"Error: not a directory: {path}", err=True, fg="red")
        raise typer.Exit(2)

    target_file = _resolve_baseline_path(path, baseline)
    if not target_file.exists():
        typer.secho(
            f"Error: baseline file not found at {target_file}. "
            "Run 'vigilloo baseline create' first.",
            err=True,
            fg="red",
        )
        raise typer.Exit(2)

    try:
        baseline_fps = load_baseline_fingerprints(target_file)
    except Exception as exc:
        typer.secho(f"Error reading baseline: {exc}", err=True, fg="red")
        raise typer.Exit(2) from exc

    _, _, _, findings, _ = _execute_scan(path, console)
    current_fps = [f.fingerprint for f in findings]
    diff = diff_fingerprints(current_fps, baseline_fps)

    table = Table(title=f"Baseline Diff for {target_file}")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Status")

    table.add_row(
        "New (introduced)",
        str(len(diff.added)),
        "[red]FAIL[/red]" if diff.added else "[green]OK[/green]",
    )
    table.add_row(
        "Resolved (fixed)",
        str(len(diff.removed)),
        "[green]IMPROVED[/green]" if diff.removed else "-",
    )
    table.add_row(
        "Unchanged (suppressed)",
        str(len(diff.unchanged)),
        "[dim]PERSISTENT[/dim]",
    )
    console.print(table)

    if diff.added:
        console.print(
            f"\n[bold red]{len(diff.added)} new finding(s) introduced "
            "compared to baseline.[/bold red]"
        )
        raise typer.Exit(1)

    console.print("\n[bold green]No new findings compared to baseline.[/bold green]")
    raise typer.Exit(0)


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Project root to initialise."),  # noqa: B008
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration file if present.",
    ),
    name: str | None = typer.Option(
        None,
        "--name",
        help="Project name (defaults to composer.json name or directory name).",
    ),
    framework: str = typer.Option(
        "laravel",
        "--framework",
        help="Project framework (default: laravel).",
    ),
    ci: bool | None = typer.Option(
        None,
        "--ci/--no-ci",
        help="Generate GitHub Actions CI workflow.",
    ),
    pre_commit: bool | None = typer.Option(
        None,
        "--pre-commit/--no-pre-commit",
        help="Install git pre-commit hook.",
    ),
    no_interaction: bool = typer.Option(
        False,
        "--no-interaction",
        "-n",
        help="Do not prompt for interactive input.",
    ),
) -> None:
    """Initialize a project with a starter vigilloo.yml configuration."""
    code = run_init(
        path=path,
        force=force,
        name=name,
        framework=framework,
        ci=ci,
        pre_commit=pre_commit,
        no_interaction=no_interaction,
    )
    raise typer.Exit(code)


@app.command()
def doctor(
    path: Path = typer.Argument(Path("."), help="Project root to diagnose."),  # noqa: B008
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit diagnostic output as JSON.",
    ),
) -> None:
    """Diagnose environment, framework detection, and project health."""
    code = run_doctor(path=path, as_json=output_json)
    raise typer.Exit(code)


@app.command()
def explain(
    target: str = typer.Argument(..., help="Finding fingerprint, ID, or rule to explain."),
    path: Path = typer.Option(  # noqa: B008
        Path("."), "-p", "--project", "--path", help="Project root to inspect."
    ),
    cwe: str | None = typer.Option(None, "--cwe", help="Filter by CWE identifier."),
) -> None:
    """Print one finding's evidence path step by step with CWE context and remediation."""
    code = run_explain(target=target, path=path, cwe=cwe)
    raise typer.Exit(code)


graph_app = typer.Typer(
    name="graph",
    help="Query, export, and inspect the application knowledge graph.",
    no_args_is_help=True,
)
app.add_typer(graph_app, name="graph")


@graph_app.command("export")
def graph_export_cmd(
    path: Path = typer.Argument(Path("."), help="Project root to export graph from."),  # noqa: B008
    output_format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Export format (json, graphml).",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None,
        "-o",
        "--output",
        help="Output file path (prints to stdout if omitted).",
    ),
) -> None:
    """Export the knowledge graph to JSON or GraphML."""
    code = run_graph_export(path=path, output_format=output_format, output_file=output)
    raise typer.Exit(code)


@graph_app.command("routes")
def graph_routes_cmd(
    path: Path = typer.Argument(Path("."), help="Project root to inspect routes for."),  # noqa: B008
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Display the HTTP route attack-surface inventory."""
    code = run_graph_routes(path=path, as_json=as_json)
    raise typer.Exit(code)


@graph_app.command("stats")
def graph_stats_cmd(
    path: Path = typer.Argument(Path("."), help="Project root to inspect graph stats for."),  # noqa: B008
    as_json: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Display knowledge graph composition and resolution statistics."""
    code = run_graph_stats(path=path, as_json=as_json)
    raise typer.Exit(code)


@graph_app.command("build")
def graph_build_cmd(
    path: Path = typer.Argument(Path("."), help="Project root to build graph for."),  # noqa: B008
) -> None:
    """Build and update the knowledge graph in the workspace store."""
    code = run_graph_build(path=path)
    raise typer.Exit(code)
