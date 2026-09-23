"""Tests for `vigilloo explain` command."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def _setup_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def test_explain_live_lookup(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    # First create a baseline or run a scan to obtain a valid finding fingerprint
    res = runner.invoke(app, ["baseline", "create", str(root)])
    assert res.exit_code == 0
    baseline_file = root / ".vigilloo" / "baseline.json"
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert len(data) > 0
    target_fp = data[0]["fingerprint"]

    # Explain by full fingerprint
    result = runner.invoke(app, ["explain", target_fp, "--project", str(root)])
    assert result.exit_code == 0
    assert "Finding Summary" in result.stdout
    assert "Evidence Path" in result.stdout
    assert "Remediation" in result.stdout


def test_explain_with_cwe(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    res = runner.invoke(app, ["baseline", "create", str(root)])
    assert res.exit_code == 0
    baseline_file = root / ".vigilloo" / "baseline.json"
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    target_fp = data[0]["fingerprint"]

    result = runner.invoke(app, ["explain", target_fp, "--project", str(root), "--cwe", "CWE-89"])
    assert result.exit_code == 0
    assert "CWE" in result.stdout


def test_explain_partial_prefix(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    res = runner.invoke(app, ["baseline", "create", str(root)])
    assert res.exit_code == 0
    baseline_file = root / ".vigilloo" / "baseline.json"
    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    target_fp = data[0]["fingerprint"]
    prefix = target_fp[:8]

    result = runner.invoke(app, ["explain", prefix, "--project", str(root)])
    assert result.exit_code == 0
    assert "Finding Summary" in result.stdout


def test_explain_from_database(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    # Run a normal scan to populate .vigilloo/vigilloo.db
    scan_res = runner.invoke(app, ["scan", str(root)])
    assert scan_res.exit_code in (0, 1)

    # Get fingerprint from baseline
    res = runner.invoke(app, ["baseline", "create", str(root)])
    assert res.exit_code == 0
    data = json.loads((root / ".vigilloo" / "baseline.json").read_text(encoding="utf-8"))
    target_fp = data[0]["fingerprint"]

    result = runner.invoke(app, ["explain", target_fp, "--project", str(root)])
    assert result.exit_code == 0
    assert "Finding Summary" in result.stdout


def test_explain_not_found(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    result = runner.invoke(
        app, ["explain", "non-existent-fingerprint-12345", "--project", str(root)]
    )
    assert result.exit_code == 1
    assert "No findings matching" in result.stdout
