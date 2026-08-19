"""The --format flag, and the stdout discipline the machine formats need."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")
UNPARSEABLE = Path("tests/fixtures/laravel-unparseable")


def _copy(fixture: Path, tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def test_default_format_is_still_the_terminal_report(tmp_path: Path) -> None:
    """The flag is additive. Nobody's existing invocation changes behaviour."""
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 1
    assert "Coverage:" in result.stdout


def test_unknown_format_is_rejected_with_the_config_exit_code(tmp_path: Path) -> None:
    """docs/19-cli gives 2 to a usage error. A typo must not silently fall
    back to the terminal format and produce output a pipeline cannot parse.
    """
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(app, ["scan", str(root), "--format", "yaml"])
    assert result.exit_code == 2


def test_coverage_warnings_go_to_stderr_under_json(tmp_path: Path) -> None:
    """The unparseable fixture prints a syntax-error caveat. Under --format
    json that caveat must not land in the middle of the document.
    """
    root = _copy(UNPARSEABLE, tmp_path)
    result = runner.invoke(app, ["scan", str(root), "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.stdout)
    assert payload["coverage"]["files_with_errors"] >= 1


def test_json_exit_code_matches_the_terminal_run(tmp_path: Path) -> None:
    """Format changes presentation, never the verdict CI gates on."""
    root = _copy(FIXTURE, tmp_path)
    terminal = runner.invoke(app, ["scan", str(root)])
    as_json = runner.invoke(app, ["scan", str(root), "--format", "json"])
    assert terminal.exit_code == as_json.exit_code == 1


def test_empty_project_under_json_still_emits_a_parseable_document(tmp_path: Path) -> None:
    """A directory with no PHP files must not leave stdout empty under a
    machine format: `vigilloo scan bad/path --format json | jq .` is an easy
    way to hit this (a wrong path in CI, a misconfigured scan root), and an
    empty stdout with exit code 0 makes `json.loads` raise instead of telling
    the pipeline the scan found nothing.
    """
    root = tmp_path / "empty"
    root.mkdir()
    result = runner.invoke(app, ["scan", str(root), "--format", "json"], catch_exceptions=False)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["total"] == 0
    assert payload["findings"] == []


def test_empty_project_under_terminal_format_is_unchanged(tmp_path: Path) -> None:
    """The terminal path is not machine-parsed, so it keeps today's exact
    behaviour: the yellow warning and nothing else, no findings block.
    """
    root = tmp_path / "empty"
    root.mkdir()
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 0
    assert "No PHP files found" in result.stdout
    assert "Coverage:" not in result.stdout
    assert "No findings." not in result.stdout
