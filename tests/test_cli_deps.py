"""Tests for `vigilloo deps` CLI command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()


def test_deps_missing_composer_lock_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["deps", str(tmp_path)])
    assert result.exit_code == 2
    assert "composer.lock not found" in result.stdout


def test_deps_nonexistent_path_exits_2() -> None:
    result = runner.invoke(app, ["deps", "/nonexistent/xyz/abc"])
    assert result.exit_code == 2


def test_deps_clean_lockfile(tmp_path: Path) -> None:
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "guzzlehttp/guzzle",
                        "version": "7.4.5",
                        "license": ["MIT"],
                    }
                ],
                "packages-dev": [],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["deps", str(tmp_path)])
    assert result.exit_code == 0
    assert "No vulnerable dependencies detected" in result.stdout


def test_deps_vulnerable_lockfile_terminal(tmp_path: Path) -> None:
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "guzzlehttp/guzzle",
                        "version": "7.4.4",
                        "license": ["MIT"],
                    }
                ],
                "packages-dev": [],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["deps", str(tmp_path)])
    assert result.exit_code == 1
    assert "guzzlehttp" in result.stdout
    assert "CVE-2022-31090" in result.stdout or "GHSA-c24v-8rfc-w8vw" in result.stdout


def test_deps_vulnerable_lockfile_json(tmp_path: Path) -> None:
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "guzzlehttp/guzzle",
                        "version": "7.4.4",
                        "license": ["MIT"],
                    }
                ],
                "packages-dev": [],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["deps", "--json", str(tmp_path)])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["packages_count"] == 1
    assert data["vulnerabilities_count"] >= 1
    assert data["findings"][0]["package"] == "guzzlehttp/guzzle"


def test_deps_generate_sbom_cyclonedx(tmp_path: Path) -> None:
    lock = tmp_path / "composer.lock"
    lock.write_text(
        json.dumps(
            {
                "packages": [
                    {
                        "name": "guzzlehttp/guzzle",
                        "version": "7.4.4",
                        "license": ["MIT"],
                    }
                ],
                "packages-dev": [],
            }
        ),
        encoding="utf-8",
    )

    sbom_file = tmp_path / "bom.json"
    result = runner.invoke(
        app,
        ["deps", "--sbom", "cyclonedx", "-o", str(sbom_file), str(tmp_path)],
    )
    assert result.exit_code == 0
    assert sbom_file.exists()

    data = json.loads(sbom_file.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert len(data["components"]) == 1
