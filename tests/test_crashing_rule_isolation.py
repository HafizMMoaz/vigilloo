"""Tests for crashing rule isolation and manifest recording."""

import json
import shutil
import sqlite3
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.graph import load_project
from vigilloo.rules import scan_project

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def _copy(fixture: Path, tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def test_crashing_structural_rule_is_isolated_and_recorded(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    project = load_project(root)

    # Deliberately make one structural check crash
    with patch(
        "vigilloo.structural._dead_authorization_paths",
        side_effect=RuntimeError("Intentional rule crash"),
    ):
        findings = scan_project(project)
        # Scan finishes and other findings are still found
        assert len(findings) > 0
        assert "laravel.dead-authorization" in project.failed_rules
        assert "Intentional rule crash" in project.failed_rules["laravel.dead-authorization"]


def test_crashing_rule_records_in_manifest_and_exits_degraded(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)

    # When all findings are suppressed or none exist, but a rule crashed, exit code should be 3
    with patch(
        "vigilloo.structural._dead_authorization_paths",
        side_effect=RuntimeError("Broken rule plugin"),
    ):
        # Scan with high fail_on so findings don't trigger exit 1
        result = runner.invoke(
            app,
            ["scan", str(root), "--rules", "non.existent.rule", "--format", "json"],
            catch_exceptions=False,
        )
        assert result.exit_code == 3

    # Check store manifest recorded the failed rule
    db_path = root / ".vigilloo" / "vigilloo.db"
    assert db_path.exists()
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status, manifest FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    assert row[0] == "partial"
    manifest = json.loads(row[1])
    assert "failed_rules" in manifest
    assert "laravel.dead-authorization" in manifest["failed_rules"]
