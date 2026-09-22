"""Tests for `vigilloo graph` subcommands."""

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


def test_graph_routes_table_and_json(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)

    # Human table output
    res = runner.invoke(app, ["graph", "routes", str(root)])
    assert res.exit_code == 0
    assert "Discovered" in res.stdout or "Route" in res.stdout

    # JSON output
    res_json = runner.invoke(app, ["graph", "routes", str(root), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert isinstance(data, list)
    assert len(data) > 0
    assert all("verbs" in r and "uri" in r and "auth_required" in r for r in data)


def test_graph_stats_table_and_json(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)

    # Human stats output
    res = runner.invoke(app, ["graph", "stats", str(root)])
    assert res.exit_code == 0
    assert "Total Nodes" in res.stdout
    assert "Total Edges" in res.stdout

    # JSON output
    res_json = runner.invoke(app, ["graph", "stats", str(root), "--json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert "total_nodes" in data
    assert "total_edges" in data
    assert data["total_nodes"] > 0


def test_graph_export_json(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)

    res = runner.invoke(app, ["graph", "export", str(root), "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "nodes" in data
    assert "edges" in data
    assert isinstance(data["nodes"], list)
    assert isinstance(data["edges"], list)


def test_graph_export_graphml(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)

    res = runner.invoke(app, ["graph", "export", str(root), "--format", "graphml"])
    assert res.exit_code == 0
    assert "<graphml" in res.stdout
    assert "</graphml>" in res.stdout


def test_graph_build(tmp_path: Path) -> None:
    root = _setup_project(tmp_path)

    res = runner.invoke(app, ["graph", "build", str(root)])
    assert res.exit_code == 0
    assert "Successfully built knowledge graph" in res.stdout

    # Verify that database exists
    db_file = root / ".vigilloo" / "vigilloo.db"
    assert db_file.is_file()

    # Subsequent export reads from DB
    res_exp = runner.invoke(app, ["graph", "export", str(root), "--format", "json"])
    assert res_exp.exit_code == 0
    data = json.loads(res_exp.stdout)
    assert len(data["nodes"]) > 0
