"""Tests for incremental scanning via symbol_cache and summary_cache."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo import store
from vigilloo.cli import app
from vigilloo.graph import load_project
from vigilloo.symbols import PARSER_VERSION, FileSymbols
from vigilloo.workspace import Workspace

FIXTURE = Path("tests/fixtures/laravel-minimal")


def _copy(fixture: Path, tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def test_symbol_cache_roundtrip(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    conn = store.connect(workspace)

    syms = FileSymbols(namespace="App\\Test", imports={}, classes={}, traits={})
    store.save_symbols(conn, "sha123", PARSER_VERSION, syms)

    loaded = store.load_symbols(conn, "sha123", PARSER_VERSION)
    assert loaded is not None
    assert loaded.namespace == "App\\Test"

    # Mismatched version should return None (invalidation)
    assert store.load_symbols(conn, "sha123", "9.9.9") is None
    # Mismatched sha should return None
    assert store.load_symbols(conn, "wrong_sha", PARSER_VERSION) is None


def test_load_project_populates_and_hits_symbol_cache(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    workspace = Workspace.open(root)
    conn = store.connect(workspace)

    # First load: populates symbol_cache
    project1 = load_project(root, conn=conn)
    assert len(project1.symbols) > 0

    count = conn.execute("SELECT count(*) FROM symbol_cache").fetchone()[0]
    assert count == len(project1.files)

    # Second load: reuses symbol_cache
    project2 = load_project(root, conn=conn)
    assert set(project1.symbols.keys()) == set(project2.symbols.keys())
    for rel_path, s1 in project1.symbols.items():
        s2 = project2.symbols[rel_path]
        assert s1.namespace == s2.namespace
        assert set(s1.classes.keys()) == set(s2.classes.keys())


def test_single_file_modification_invalidates_only_that_file(tmp_path: Path) -> None:
    root = _copy(FIXTURE, tmp_path)
    workspace = Workspace.open(root)
    conn = store.connect(workspace)

    project1 = load_project(root, conn=conn)
    target_file = root / "app" / "Http" / "Controllers" / "UserController.php"
    assert target_file.exists()

    rel_path = target_file.relative_to(root)
    old_sha = project1.digests[rel_path]

    # Modify the file
    original_content = target_file.read_text(encoding="utf-8")
    target_file.write_text(original_content + "\n// modified\n", encoding="utf-8")

    # Load again
    project2 = load_project(root, conn=conn)
    new_sha = project2.digests[rel_path]
    assert new_sha != old_sha

    # Other files still have their original shas and hit the cache
    for other_rel in project1.symbols.keys():
        if other_rel != rel_path:
            old_fsha = project1.digests[other_rel]
            assert project2.digests[other_rel] == old_fsha
            cached = store.load_symbols(conn, old_fsha, PARSER_VERSION)
            assert cached is not None


def test_rescan_unchanged_project_produces_identical_findings(tmp_path: Path) -> None:
    runner = CliRunner()
    root = _copy(FIXTURE, tmp_path)

    res1 = runner.invoke(app, ["scan", str(root), "--format", "json"], catch_exceptions=False)
    assert res1.exit_code == 1
    doc1 = json.loads(res1.stdout)

    res2 = runner.invoke(app, ["scan", str(root), "--format", "json"], catch_exceptions=False)
    assert res2.exit_code == 1
    doc2 = json.loads(res2.stdout)

    assert doc1["summary"] == doc2["summary"]
    assert len(doc1["findings"]) == len(doc2["findings"])
    for f1, f2 in zip(doc1["findings"], doc2["findings"], strict=True):
        assert f1["id"] == f2["id"]
        assert f1["fingerprint"] == f2["fingerprint"]
        assert f1["rule_id"] == f2["rule_id"]
        assert f1["location"] == f2["location"]
