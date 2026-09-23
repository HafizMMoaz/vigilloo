"""Implementation of the `vigilloo init` command.

Writes starter configuration (vigilloo.yml), offers optional GitHub Actions CI
workflow and Git pre-commit hook.
"""

import json
import sys
from pathlib import Path

from rich.console import Console

STARTER_CONFIG = """# Vigilloo configuration file
version: 1

project:
  name: {name}
  framework: {framework}

scan:
  exclude:
    - "storage/**"
    - "database/seeders/**"
    - "tests/**"
  severity: medium
  fail_on: high

rules:
  disable: []

taint:
  sources: []
  sanitizers: []
"""

GITHUB_WORKFLOW = """name: Vigilloo Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  vigilloo:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install Vigilloo
        run: pip install vigilloo
      - name: Run Vigilloo Scan
        run: vigilloo scan
"""

PRE_COMMIT_HOOK = """#!/bin/sh
vigilloo scan
"""


def detect_project_name(path: Path) -> str:
    """Infer project name from composer.json or directory name."""
    composer_path = path / "composer.json"
    if composer_path.is_file():
        try:
            data = json.loads(composer_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict) and "name" in data and isinstance(data["name"], str):
                return data["name"]
        except Exception:
            pass
    return path.resolve().name or "my-app"


def run_init(
    path: Path,
    force: bool = False,
    name: str | None = None,
    framework: str = "laravel",
    ci: bool | None = None,
    pre_commit: bool | None = None,
    no_interaction: bool = False,
    console: Console | None = None,
) -> int:
    """Execute vigilloo init logic."""
    if console is None:
        console = Console()

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    config_file = resolved_path / "vigilloo.yml"
    if config_file.exists() and not force:
        if no_interaction or not sys.stdin.isatty():
            console.print(
                f"[yellow]vigilloo.yml already exists in {path}. Use --force to overwrite.[/yellow]"
            )
            return 1
        # Interactive prompt
        prompt = f"vigilloo.yml already exists in {path}. Overwrite? [y/N]: "
        response = input(prompt).strip().lower()
        if response not in ("y", "yes"):
            console.print("[yellow]Initialization cancelled.[/yellow]")
            return 0

    project_name = name or detect_project_name(resolved_path)

    interactive = not no_interaction and sys.stdin.isatty()
    if interactive and name is None:
        entered_name = input(f"Project name [{project_name}]: ").strip()
        if entered_name:
            project_name = entered_name

    # Write vigilloo.yml
    config_content = STARTER_CONFIG.format(name=project_name, framework=framework)
    config_file.write_text(config_content, encoding="utf-8")
    console.print(f"[green]✓ Created vigilloo.yml in {resolved_path}[/green]")

    # Check CI workflow
    want_ci = ci
    if want_ci is None and interactive:
        response = input("Generate GitHub Actions CI workflow? [y/N]: ").strip().lower()
        want_ci = response in ("y", "yes")

    if want_ci:
        workflows_dir = resolved_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        ci_file = workflows_dir / "vigilloo.yml"
        ci_file.write_text(GITHUB_WORKFLOW, encoding="utf-8")
        console.print(f"[green]✓ Created CI workflow: {ci_file}[/green]")

    # Check pre-commit hook
    want_pre_commit = pre_commit
    git_dir = resolved_path / ".git"
    if want_pre_commit is None and interactive and git_dir.is_dir():
        response = input("Install Git pre-commit hook? [y/N]: ").strip().lower()
        want_pre_commit = response in ("y", "yes")

    if want_pre_commit:
        if not git_dir.is_dir():
            console.print("[yellow]! Git repository not found; skipping pre-commit hook.[/yellow]")
        else:
            hooks_dir = git_dir / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            hook_file = hooks_dir / "pre-commit"
            if hook_file.exists():
                existing_content = hook_file.read_text(encoding="utf-8", errors="replace")
                if "vigilloo scan" not in existing_content:
                    hook_file.write_text(
                        existing_content.rstrip() + "\n\nvigilloo scan\n",
                        encoding="utf-8",
                    )
                    console.print(f"[green]✓ Appended vigilloo scan to {hook_file}[/green]")
                else:
                    console.print(
                        f"[green]✓ Pre-commit hook already configured in {hook_file}[/green]"
                    )
            else:
                hook_file.write_text(PRE_COMMIT_HOOK, encoding="utf-8")
                console.print(f"[green]✓ Installed pre-commit hook in {hook_file}[/green]")
            # Make executable
            try:
                hook_file.chmod(hook_file.stat().st_mode | 0o111)
            except OSError:
                pass

    console.print(
        f"[bold green]Vigilloo initialized successfully for '{project_name}'.[/bold green] "
        "Run `vigilloo scan` to start scanning."
    )
    return 0
