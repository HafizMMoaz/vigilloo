"""The `vigilloo scan` command itself.

Which findings the fixture produces is declared in
`tests/fixtures/laravel-minimal/expected.yml` and asserted by `tests/test_corpus.py`. What
is left here is the command's own behaviour: exit codes, usage errors, and whether the
report renders everything a finding carries.
"""

from pathlib import Path

from harness import scan_fixture
from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()


def test_scan_renders_every_step_of_every_finding(fixture_project: Path) -> None:
    """The evidence path is the product, so all of it has to reach the terminal.

    Derived from the scan rather than hard-coded: this is a claim about report.py, and
    pinning it to particular fixture findings would make it a second, weaker copy of
    expected.yml that goes stale the first time the fixture grows a case.
    """
    result = runner.invoke(app, ["scan", str(fixture_project)])
    out = result.stdout
    findings = scan_fixture(fixture_project)
    assert findings

    for finding in findings:
        assert finding.title in out
        assert finding.rule_id in out
        for cwe in finding.cwe:
            assert cwe in out
        for step in finding.evidence_path:
            assert f"{step.span.file.name}:{step.span.start_line}" in out

    assert f"{len(findings)} findings" in out


def test_scan_exit_code_is_one_when_findings_exist(fixture_project: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixture_project)])
    assert result.exit_code == 1


def test_scan_of_clean_project_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Empty.php").write_text("<?php\nclass Empty_ {}\n")
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No findings" in result.stdout


def test_nonexistent_path_is_a_usage_error() -> None:
    """Reporting "no findings" for a path that was never scanned is a lie."""
    result = runner.invoke(app, ["scan", "/does/not/exist/anywhere"])
    assert result.exit_code == 2
    assert "No findings" not in result.stdout


def test_file_argument_is_a_usage_error(tmp_path: Path) -> None:
    target = tmp_path / "single.php"
    target.write_text("<?php\nclass A {}\n")
    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == 2


def test_directory_with_no_php_files_warns_rather_than_claiming_clean(
    tmp_path: Path,
) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "no php files" in result.stdout.lower()


# The two dash characters below are the values under test. This file is the
# single sanctioned exception to the project-wide no-dash rule; they must not
# be replaced with hyphens or the assertion becomes meaningless.
def test_no_em_dashes_in_output(fixture_project: Path) -> None:
    """Project convention: hyphens only."""
    result = runner.invoke(app, ["scan", str(fixture_project)])
    assert "—" not in result.stdout
    assert "–" not in result.stdout
