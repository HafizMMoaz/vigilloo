"""Implementation of the `vigilloo doctor` command.

Provides environment and project diagnostics: Python version, tree-sitter
grammar health, detected framework, PHP file counts, parse success rate,
configuration validity, and database status.
"""

import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from . import __version__
from .config import check_config_file
from .laravel.detect import read_autoload
from .parser import parse_source
from .workspace import Workspace
from .workspace.migrations import SCHEMA_VERSION


@dataclass
class DiagnosticResult:
    category: str
    name: str
    status: str  # "ok", "warning", "error"
    message: str
    details: list[str] = field(default_factory=list)


def check_python_environment() -> DiagnosticResult:
    """Verify Python version and runtime environment."""
    version_str = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info < (3, 12):  # noqa: UP036
        return DiagnosticResult(
            category="Environment",
            name="Python Version",
            status="error",
            message=f"Python {version_str} (Python 3.12+ is required)",
        )
    return DiagnosticResult(
        category="Environment",
        name="Python Version",
        status="ok",
        message=f"Python {version_str} on {sys.platform}",
    )


def check_treesitter_parser() -> DiagnosticResult:
    """Test tree-sitter PHP grammar and parser operation."""
    try:
        sample = b"<?php class HealthCheck { public function ok(): bool { return true; } }"
        parsed = parse_source(Path("check.php"), sample)
        if parsed.has_errors:
            return DiagnosticResult(
                category="Parser",
                name="Tree-sitter PHP",
                status="error",
                message="Parser encountered unexpected errors parsing basic PHP syntax.",
            )
        return DiagnosticResult(
            category="Parser",
            name="Tree-sitter PHP",
            status="ok",
            message="Grammar and parser operational.",
        )
    except Exception as exc:
        return DiagnosticResult(
            category="Parser",
            name="Tree-sitter PHP",
            status="error",
            message=f"Tree-sitter initialization failure: {exc}",
        )


def check_project_framework(root: Path) -> DiagnosticResult:
    """Detect framework and inspect composer.json."""
    composer_file = root / "composer.json"
    indicators: list[str] = []

    has_composer = composer_file.is_file()
    composer_data: dict[str, Any] = {}
    if has_composer:
        try:
            raw = composer_file.read_text(encoding="utf-8", errors="replace")
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                composer_data = parsed
        except Exception:
            pass

    # Check Laravel markers
    if (root / "artisan").is_file():
        indicators.append("artisan CLI present")
    if (root / "bootstrap" / "app.php").is_file():
        indicators.append("bootstrap/app.php present")

    require = composer_data.get("require", {})
    if isinstance(require, dict) and "laravel/framework" in require:
        indicators.append(f"laravel/framework: {require['laravel/framework']}")

    workspace = Workspace(root=root, dir=root / ".vigilloo")
    autoload = read_autoload(workspace)
    prefix_count = len(autoload.roots)

    if indicators:
        details = [f"Indicators: {', '.join(indicators)}", f"PSR-4 namespaces: {prefix_count}"]
        if autoload.rejected:
            details.append(f"Rejected autoload mappings: {len(autoload.rejected)}")
        return DiagnosticResult(
            category="Project",
            name="Framework",
            status="ok",
            message="Laravel",
            details=details,
        )

    if has_composer:
        return DiagnosticResult(
            category="Project",
            name="Framework",
            status="ok",
            message=f"Generic PHP (Composer) with {prefix_count} PSR-4 root(s)",
        )

    return DiagnosticResult(
        category="Project",
        name="Framework",
        status="warning",
        message="Standalone PHP (no composer.json found)",
    )


def check_php_files_and_parse_rate(root: Path) -> DiagnosticResult:
    """Count PHP files and evaluate parse success rate."""
    ignore_dirs = {".git", "vendor", "node_modules", "storage", ".vigilloo"}
    php_files: list[Path] = []

    for path in root.rglob("*.php"):
        # Ignore files inside ignored directories
        if any(part in ignore_dirs for part in path.parts):
            continue
        php_files.append(path)

    total_files = len(php_files)
    if total_files == 0:
        return DiagnosticResult(
            category="Files",
            name="PHP Files & Parse Rate",
            status="warning",
            message="No PHP files found in project",
        )

    clean_count = 0
    error_count = 0
    unreadable_count = 0

    # Test parse each file
    for p in php_files:
        try:
            source = p.read_bytes()
            parsed = parse_source(p, source)
            if parsed.has_errors:
                error_count += 1
            else:
                clean_count += 1
        except Exception:
            unreadable_count += 1

    rate = (clean_count / total_files) * 100.0 if total_files > 0 else 100.0
    status = "ok"
    if rate < 80.0 or unreadable_count > 0:
        status = "warning"

    details = [
        f"Total PHP files: {total_files}",
        f"Clean syntax: {clean_count}",
        f"Syntax errors (partial analysis): {error_count}",
    ]
    if unreadable_count > 0:
        details.append(f"Unreadable files: {unreadable_count}")

    return DiagnosticResult(
        category="Files",
        name="PHP Files & Parse Rate",
        status=status,
        message=f"{clean_count}/{total_files} files parsed cleanly ({rate:.1f}%)",
        details=details,
    )


def check_configuration(root: Path) -> DiagnosticResult:
    """Validate vigilloo.yml configuration file."""
    config_file = root / "vigilloo.yml"
    if not config_file.is_file():
        return DiagnosticResult(
            category="Configuration",
            name="vigilloo.yml",
            status="ok",
            message=(
                "No configuration file found (defaults in use; run `vigilloo init` to create one)"
            ),
        )

    errors = check_config_file(config_file)
    if errors:
        return DiagnosticResult(
            category="Configuration",
            name="vigilloo.yml",
            status="error",
            message="Configuration file contains errors",
            details=errors,
        )

    return DiagnosticResult(
        category="Configuration",
        name="vigilloo.yml",
        status="ok",
        message="Valid configuration file",
    )


def check_workspace_database(root: Path) -> DiagnosticResult:
    """Inspect .vigilloo directory and SQLite database."""
    dot_vigilloo = root / ".vigilloo"
    if not dot_vigilloo.is_dir():
        return DiagnosticResult(
            category="Database",
            name="Workspace Store",
            status="ok",
            message="No workspace created yet (created automatically on first scan)",
        )

    db_path = dot_vigilloo / "vigilloo.db"
    if not db_path.is_file():
        return DiagnosticResult(
            category="Database",
            name="Workspace Store",
            status="ok",
            message=".vigilloo/ directory exists, no database created yet",
        )

    try:
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute("SELECT value FROM schema_meta WHERE key = 'version'").fetchone()
            schema_ver = int(row[0]) if row else 0

            scan_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

            status = "ok"
            details = [
                f"Schema version: {schema_ver} (current: {SCHEMA_VERSION})",
                f"Scans recorded: {scan_count}",
                f"Findings in database: {findings_count}",
            ]
            if schema_ver > SCHEMA_VERSION:
                status = "error"
                details.append("Database schema is newer than this Vigilloo version!")

            return DiagnosticResult(
                category="Database",
                name="Workspace Store",
                status=status,
                message=f"Database operational ({scan_count} scans recorded)",
                details=details,
            )
        finally:
            conn.close()
    except Exception as exc:
        return DiagnosticResult(
            category="Database",
            name="Workspace Store",
            status="warning",
            message=f"Could not read database: {exc}",
        )


def run_doctor(
    path: Path,
    as_json: bool = False,
    console: Console | None = None,
) -> int:
    """Execute vigilloo doctor diagnostics."""
    if console is None:
        console = Console()

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    results: list[DiagnosticResult] = [
        check_python_environment(),
        check_treesitter_parser(),
        check_project_framework(resolved_path),
        check_php_files_and_parse_rate(resolved_path),
        check_configuration(resolved_path),
        check_workspace_database(resolved_path),
    ]

    has_error = any(r.status == "error" for r in results)
    config_error = any(r.category == "Configuration" and r.status == "error" for r in results)

    if as_json:
        data = {
            "version": __version__,
            "root": str(resolved_path),
            "healthy": not has_error,
            "checks": [
                {
                    "category": r.category,
                    "name": r.name,
                    "status": r.status,
                    "message": r.message,
                    "details": r.details,
                }
                for r in results
            ],
        }
        print(json.dumps(data, indent=2))  # noqa: T201
    else:
        console.print(
            f"\n[bold]Vigilloo Doctor Diagnostics[/bold] for [cyan]{resolved_path}[/cyan]\n"
        )
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Check", style="bold")
        table.add_column("Status")
        table.add_column("Result")

        for r in results:
            if r.status == "ok":
                status_badge = "[green]✓ OK[/green]"
            elif r.status == "warning":
                status_badge = "[yellow]! WARN[/yellow]"
            else:
                status_badge = "[red]✗ FAIL[/red]"

            msg = r.message
            if r.details:
                msg += "\n" + "\n".join(f"  • {d}" for d in r.details)

            table.add_row(f"{r.category}: {r.name}", status_badge, msg)

        console.print(table)
        console.print()

        if has_error:
            console.print(
                "[bold red]Doctor reported errors. Please address items marked with ✗.[/bold red]\n"
            )
        else:
            console.print("[bold green]System and project are ready for scanning.[/bold green]\n")

    if config_error:
        return 4
    if has_error:
        return 3
    return 0
