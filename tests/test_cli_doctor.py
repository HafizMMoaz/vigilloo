"""Tests for `vigilloo doctor` command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vigilloo import __version__
from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_doctor_terminal_output_minimal_fixture() -> None:
    result = runner.invoke(app, ["doctor", str(FIXTURE)])
    assert result.exit_code == 0
    assert "Vigilloo Doctor Diagnostics" in result.stdout
    assert "Laravel" in result.stdout
    assert "Tree-sitter PHP" in result.stdout
    assert "files parsed cleanly" in result.stdout


def test_doctor_json_output() -> None:
    result = runner.invoke(app, ["doctor", "--json", str(FIXTURE)])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == __version__
    assert data["healthy"] is True
    categories = {check["category"] for check in data["checks"]}
    assert "Environment" in categories
    assert "Parser" in categories
    assert "Project" in categories
    assert "Files" in categories
    assert "Configuration" in categories
    assert "Database" in categories


def test_doctor_invalid_config_exits_4(tmp_path: Path) -> None:
    config = tmp_path / "vigilloo.yml"
    config.write_text("scan:\n  severity: invalid_severity\n", encoding="utf-8")

    result = runner.invoke(app, ["doctor", str(tmp_path)])
    assert result.exit_code == 4
    assert "Configuration file contains errors" in result.stdout


def test_doctor_malformed_yaml_exits_4(tmp_path: Path) -> None:
    config = tmp_path / "vigilloo.yml"
    config.write_text("scan: [unclosed list\n", encoding="utf-8")

    result = runner.invoke(app, ["doctor", str(tmp_path)])
    assert result.exit_code == 4
    assert "YAML parse error" in result.stdout


def test_doctor_nonexistent_path_exits_2() -> None:
    result = runner.invoke(app, ["doctor", "/nonexistent/directory/xyz"])
    assert result.exit_code == 2


def test_doctor_file_with_syntax_errors(tmp_path: Path) -> None:
    bad_php = tmp_path / "bad.php"
    bad_php.write_text("<?php function broken( {", encoding="utf-8")

    result = runner.invoke(app, ["doctor", "--json", str(tmp_path)])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    files_check = next(c for c in data["checks"] if c["name"] == "PHP Files & Parse Rate")
    assert "Syntax errors (partial analysis): 1" in files_check["details"]
