"""Tests for scan/review options: -o/--output, --severity, --fail-on, --rules, --exclude-rules."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def _copy(fixture: Path, tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def test_scan_output_flag_json(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    out_file = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(root), "--format", "json", "-o", str(out_file)])
    assert result.exit_code == 1
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["summary"]["total"] > 0
    assert len(data["findings"]) > 0


def test_scan_output_flag_terminal(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    out_file = tmp_path / "report.txt"
    result = runner.invoke(app, ["scan", str(root), "-o", str(out_file)])
    assert result.exit_code == 1
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Coverage:" in content


def test_scan_severity_filtering(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(root), "--format", "json", "--severity", "critical"],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["summary"]["total"] > 0
    assert all(f["severity"] == "critical" for f in data["findings"])


def test_scan_rules_filter_and_glob(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(root), "--format", "json", "--rules", "laravel.no-throttle"],
        catch_exceptions=False,
    )
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert len(data["findings"]) > 0
    assert all(f["rule_id"] == "laravel.no-throttle" for f in data["findings"])


def test_scan_exclude_rules_filter(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(root), "--format", "json", "--exclude-rules", "laravel.*"],
        catch_exceptions=False,
    )
    data = json.loads(result.stdout)
    assert all(not f["rule_id"].startswith("laravel.") for f in data["findings"])


def test_scan_fail_on_threshold(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    # Filter to only medium findings
    # If fail-on is critical, exit code should be 0 because highest finding is medium
    result = runner.invoke(
        app,
        [
            "scan",
            str(root),
            "--format",
            "json",
            "--rules",
            "laravel.no-throttle",
            "--fail-on",
            "critical",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0

    # If fail-on is medium, exit code should be 1
    result_fail = runner.invoke(
        app,
        [
            "scan",
            str(root),
            "--format",
            "json",
            "--rules",
            "laravel.no-throttle",
            "--fail-on",
            "medium",
        ],
        catch_exceptions=False,
    )
    assert result_fail.exit_code == 1


def test_review_output_flag(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    out_file = tmp_path / "review.json"
    result = runner.invoke(app, ["review", str(root), "--format", "json", "-o", str(out_file)])
    assert result.exit_code in (0, 1)
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "findings" in data
