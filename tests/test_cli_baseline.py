"""Tests for `vigilloo baseline` commands."""

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


def test_baseline_create_default_path(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    result = runner.invoke(app, ["baseline", "create", str(root)])
    assert result.exit_code == 0
    assert "Created baseline with" in result.stdout

    baseline_file = root / ".vigilloo" / "baseline.json"
    assert baseline_file.is_file()

    data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) > 0
    assert all("fingerprint" in item and "rule_id" in item for item in data)

    # Check deterministic sort
    keys = [(item["fingerprint"], item["rule_id"], item["location"]) for item in data]
    assert keys == sorted(keys)


def test_baseline_create_custom_output(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    custom_file = root / "custom-base.json"
    result = runner.invoke(app, ["baseline", "create", str(root), "-o", str(custom_file)])
    assert result.exit_code == 0
    assert custom_file.is_file()


def test_baseline_create_refuses_overwrite_without_force(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    # First create
    res1 = runner.invoke(app, ["baseline", "create", str(root)])
    assert res1.exit_code == 0

    # Second create without --force
    res2 = runner.invoke(app, ["baseline", "create", str(root)])
    assert res2.exit_code == 1
    assert "already exists" in res2.stdout

    # Third create with --force
    res3 = runner.invoke(app, ["baseline", "create", str(root), "--force"])
    assert res3.exit_code == 0


def test_baseline_diff_clean(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    runner.invoke(app, ["baseline", "create", str(root)])

    result = runner.invoke(app, ["baseline", "diff", str(root)])
    assert result.exit_code == 0
    assert "No new findings compared to baseline" in result.stdout


def test_baseline_diff_with_new_findings_and_update(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    runner.invoke(app, ["baseline", "create", str(root)])

    # Introduce a new unauthenticated state-changing route
    api_routes = root / "routes" / "api.php"
    api_routes.write_text(
        api_routes.read_text(encoding="utf-8")
        + "\nRoute::post('/new-public-api', [OrderController::class, 'index']);\n",
        encoding="utf-8",
    )

    # Diff should detect the new finding and exit 1
    res_diff = runner.invoke(app, ["baseline", "diff", str(root)])
    assert res_diff.exit_code == 1
    assert "1 new finding(s) introduced" in res_diff.stdout

    # Update should refresh the baseline
    res_update = runner.invoke(app, ["baseline", "update", str(root)])
    assert res_update.exit_code == 0
    assert "Baseline updated" in res_update.stdout

    # Subsequent diff should now be clean
    res_diff2 = runner.invoke(app, ["baseline", "diff", str(root)])
    assert res_diff2.exit_code == 0


def test_baseline_diff_nonexistent_baseline_exits_2(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    result = runner.invoke(app, ["baseline", "diff", str(root)])
    assert result.exit_code == 2
    assert "not found" in result.stdout.lower() or "not found" in (result.stderr or "").lower()


def test_baseline_invalid_json_exits_2(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)
    baseline_file = root / ".vigilloo" / "baseline.json"
    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    baseline_file.write_text("{not valid json", encoding="utf-8")

    result = runner.invoke(app, ["baseline", "diff", str(root)])
    assert result.exit_code == 2
