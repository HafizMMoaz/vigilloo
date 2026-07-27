import shutil
import sqlite3
from pathlib import Path

from typer.testing import CliRunner

from vigilloo import __version__
from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_records_what_it_printed(tmp_path: Path) -> None:
    """The store holds this scan, and holds the same findings the terminal showed."""
    # Copied without its .vigilloo/, because scanning the fixture in place accumulates a scan
    # row per run - every other test that invokes `scan` on it adds one - and the count below
    # is the point of the test.
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 1

    conn = sqlite3.connect(root / ".vigilloo" / "vigilloo.db")
    scans = conn.execute("SELECT id, status FROM scans").fetchall()
    assert len(scans) == 1
    assert scans[0][1] == "completed"

    # The join is part of the assertion: a finding whose file_id never resolved drops out of
    # it and fails the count, so a row that stored a location the report could not is caught.
    stored = conn.execute(
        "SELECT f.rule_id, files.path, f.start_line FROM findings f "
        "JOIN files ON files.id = f.file_id WHERE f.scan_id = ?",
        (scans[0][0],),
    ).fetchall()
    assert len(stored) == 10
    for rule_id, path, start_line in stored:
        assert rule_id in result.stdout
        assert f"{path}:{start_line}" in result.stdout
