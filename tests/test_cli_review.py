"""Tests for `vigilloo review` command."""

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


def test_review_clean_when_baseline_matches(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    # Create baseline
    res_base = runner.invoke(app, ["baseline", "create", str(root)])
    assert res_base.exit_code == 0

    # Review against baseline
    res_rev = runner.invoke(app, ["review", str(root)])
    assert res_rev.exit_code == 0
    assert "Review clean: no new findings introduced." in res_rev.stdout


def test_review_reports_only_new_finding(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    runner.invoke(app, ["baseline", "create", str(root)])

    # Introduce a new route
    api_routes = root / "routes" / "api.php"
    api_routes.write_text(
        api_routes.read_text(encoding="utf-8")
        + "\nRoute::post('/review-test-endpoint', [OrderController::class, 'index']);\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["review", str(root)])
    assert result.exit_code == 1
    assert "laravel.unauthenticated-route" in result.stdout
    assert "1 finding" in result.stdout


def test_review_machine_json_format(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    runner.invoke(app, ["baseline", "create", str(root)])

    api_routes = root / "routes" / "api.php"
    api_routes.write_text(
        api_routes.read_text(encoding="utf-8")
        + "\nRoute::post('/review-json-test', [OrderController::class, 'index']);\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["review", "--format", "json", str(root)])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert "findings" in data
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "laravel.unauthenticated-route"


def test_review_falls_back_to_latest_scan_history(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    # Run initial scan which records into .vigilloo/vigilloo.db
    res_scan = runner.invoke(app, ["scan", str(root)])
    assert res_scan.exit_code == 1

    # Ensure no baseline.json exists
    baseline_file = root / ".vigilloo" / "baseline.json"
    assert not baseline_file.exists()

    # Review against the recorded scan history
    res_rev1 = runner.invoke(app, ["review", str(root)])
    assert res_rev1.exit_code == 0
    assert "Review clean" in res_rev1.stdout

    # Now add new route
    api_routes = root / "routes" / "api.php"
    api_routes.write_text(
        api_routes.read_text(encoding="utf-8")
        + "\nRoute::post('/review-db-fallback', [OrderController::class, 'index']);\n",
        encoding="utf-8",
    )

    res_rev2 = runner.invoke(app, ["review", str(root)])
    assert res_rev2.exit_code == 1
    assert "1 finding" in res_rev2.stdout


def test_review_nonexistent_path() -> None:
    result = runner.invoke(app, ["review", "/nonexistent/path/xyz"])
    assert result.exit_code == 2
