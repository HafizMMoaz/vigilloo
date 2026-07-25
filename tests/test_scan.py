from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_scan_reports_the_finding_with_its_full_path() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    out = result.stdout

    assert "SQL Injection" in out
    assert "CWE-89" in out
    assert "OrderRepository.php" in out
    assert "/orders/search" in out
    assert "orderByRaw" in out
    assert "1 finding" in out


def test_scan_exit_code_is_one_when_findings_exist() -> None:
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    assert result.exit_code == 1


def test_scan_of_clean_project_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Empty.php").write_text("<?php\nclass Empty_ {}\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings" in result.stdout


# The two dash characters below are the values under test. This file is the
# single sanctioned exception to the project-wide no-dash rule; they must not
# be replaced with hyphens or the assertion becomes meaningless.
def test_no_em_dashes_in_output() -> None:
    """Project convention: hyphens only."""
    result = runner.invoke(app, ["scan", str(FIXTURE)])
    assert "—" not in result.stdout
    assert "–" not in result.stdout
