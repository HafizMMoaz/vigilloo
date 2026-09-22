"""Tests for `vigilloo init` command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()


def test_init_creates_vigilloo_yml(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path), "--no-interaction"])
    assert result.exit_code == 0
    config_path = tmp_path / "vigilloo.yml"
    assert config_path.is_file()
    content = config_path.read_text(encoding="utf-8")
    assert "version: 1" in content
    assert "framework: laravel" in content
    assert "exclude:" in content


def test_init_reads_name_from_composer_json(tmp_path: Path) -> None:
    composer = tmp_path / "composer.json"
    composer.write_text(json.dumps({"name": "vendor/sample-app"}), encoding="utf-8")

    result = runner.invoke(app, ["init", str(tmp_path), "--no-interaction"])
    assert result.exit_code == 0
    content = (tmp_path / "vigilloo.yml").read_text(encoding="utf-8")
    assert "name: vendor/sample-app" in content


def test_init_respects_explicit_name_and_framework(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "init",
            str(tmp_path),
            "--name",
            "my-custom-service",
            "--framework",
            "laravel",
            "--no-interaction",
        ],
    )
    assert result.exit_code == 0
    content = (tmp_path / "vigilloo.yml").read_text(encoding="utf-8")
    assert "name: my-custom-service" in content
    assert "framework: laravel" in content


def test_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    (tmp_path / "vigilloo.yml").write_text("original", encoding="utf-8")

    # Without --force, exits 1
    result = runner.invoke(app, ["init", str(tmp_path), "--no-interaction"])
    assert result.exit_code == 1
    assert (tmp_path / "vigilloo.yml").read_text(encoding="utf-8") == "original"

    # With --force, overwrites and exits 0
    result_force = runner.invoke(app, ["init", str(tmp_path), "--force", "--no-interaction"])
    assert result_force.exit_code == 0
    assert "version: 1" in (tmp_path / "vigilloo.yml").read_text(encoding="utf-8")


def test_init_generates_ci_workflow(tmp_path: Path) -> None:
    result = runner.invoke(app, ["init", str(tmp_path), "--ci", "--no-interaction"])
    assert result.exit_code == 0
    ci_file = tmp_path / ".github" / "workflows" / "vigilloo.yml"
    assert ci_file.is_file()
    assert "Vigilloo Security Scan" in ci_file.read_text(encoding="utf-8")


def test_init_installs_pre_commit_hook(tmp_path: Path) -> None:
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    result = runner.invoke(app, ["init", str(tmp_path), "--pre-commit", "--no-interaction"])
    assert result.exit_code == 0
    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.is_file()
    assert "vigilloo scan" in hook_file.read_text(encoding="utf-8")


def test_init_nonexistent_path() -> None:
    result = runner.invoke(app, ["init", "/nonexistent/path/12345", "--no-interaction"])
    assert result.exit_code == 2
