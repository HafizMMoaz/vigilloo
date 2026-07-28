"""Invariant 4: coverage is reported, never hidden.

A clean result over a codebase 40% of which failed to parse is a lie, so the
fraction is measured rather than described, and these tests are what keep the
measurement honest. The rates are gated in CI by docs/22-testing section
"Metrics gated in CI".
"""

import shutil
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.graph import coverage, load_project
from vigilloo.models import Coverage, WalkStats
from vigilloo.report import render_coverage
from vigilloo.rules import scan_project
from vigilloo.taint import find_taint_paths

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")
BROKEN = Path("tests/fixtures/laravel-unparseable")


def _scan(root: Path) -> Coverage:
    stats = WalkStats()
    project = load_project(root, stats)
    scan_project(project, stats)
    return coverage(project, stats)


def test_a_file_that_does_not_parse_drops_the_parse_rate_below_100() -> None:
    """The acceptance case. One of the three PHP files in the fixture is
    deliberately malformed, and the rate has to say so."""
    result = _scan(BROKEN)

    assert result.files_discovered == 3
    assert result.files_with_errors == 1
    assert result.files_parsed == 2
    assert result.parse_success_rate < 1.0
    assert result.parse_success_rate == 2 / 3


def test_the_main_fixture_parses_completely() -> None:
    """The negative case, and the one that would catch a rate stuck below 1.0.

    A metric that is never 100% is as useless as one that always is.
    """
    result = _scan(FIXTURE)

    assert result.files_discovered == 16
    assert result.parse_success_rate == 1.0
    assert result.call_resolution_rate == 1.0


def test_a_lost_trail_drops_the_resolution_rate(tmp_path: Path) -> None:
    """The walk gives up on `$unknown->handle($sort)`, so the rate must move.

    Counting only the give-ups would leave "one unresolved" meaning nothing:
    it is a catastrophe against twelve call sites and a rounding error against
    four thousand. The denominator is what makes it readable.
    """
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\C;\nRoute::post('/a', [C::class, 'a']);\n"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "C.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "class C\n"
        "{\n"
        "    public function a($request)\n"
        "    {\n"
        "        $sort = $request->input('sort');\n"
        "\n"
        "        return $unknown->handle($sort);\n"
        "    }\n"
        "}\n"
    )
    stats = WalkStats()
    project = load_project(tmp_path, stats)
    find_taint_paths(project, stats=stats)
    result = coverage(project, stats)

    assert result.calls_unresolved == 1
    assert result.calls_attempted == result.calls_resolved + 1
    assert result.call_resolution_rate < 1.0
    assert result.parse_success_rate == 1.0


def test_nothing_attempted_is_a_complete_rate_not_a_crash(tmp_path: Path) -> None:
    """The zero-denominator decision, asserted rather than left to chance.

    An empty project hid nothing, so both rates are 1.0. The alternative
    readings are a ZeroDivisionError, which turns an empty directory into a
    crash, and 0.0, which would fail the CI gate on a project with no PHP in it.
    The counts printed beside the rate are what stop a vacuous 100% from reading
    as a scanned codebase.
    """
    result = _scan(tmp_path)

    assert result.files_discovered == 0
    assert result.calls_attempted == 0
    assert result.parse_success_rate == 1.0
    assert result.call_resolution_rate == 1.0


def test_an_unreadable_file_counts_against_the_parse_rate() -> None:
    """Unreadable and unparseable are the same gap to the reader of a report.

    Asserted over the record rather than over a chmod-ed file, which behaves
    differently for root in a container than for a developer.
    """
    result = Coverage(
        files_discovered=4,
        files_unreadable=1,
        files_with_errors=1,
        calls_resolved=0,
        calls_unresolved=0,
    )

    assert result.files_parsed == 2
    assert result.parse_success_rate == 0.5


def test_both_rates_appear_in_the_scan_output(fixture_project: Path) -> None:
    result = runner.invoke(app, ["scan", str(fixture_project)])

    assert "16/16 files parsed (100.0%)" in result.stdout
    assert "call sites resolved (100.0%)" in result.stdout


def test_coverage_is_printed_before_the_findings(fixture_project: Path) -> None:
    """docs/16-reporting orders coverage second, ahead of the findings. A reader
    who stops at the first result must already have seen the blind spot."""
    out = runner.invoke(app, ["scan", str(fixture_project)]).stdout

    assert out.index("Coverage:") < out.index("SQL Injection")


def test_a_partial_scan_still_reports_its_rates(tmp_path: Path) -> None:
    """The case the invariant exists for: the report that would rather not
    mention what it could not read."""
    root = tmp_path / "project"
    shutil.copytree(BROKEN, root)
    out = runner.invoke(app, ["scan", str(root)]).stdout

    assert "syntax errors" in out
    assert "2/3 files parsed (66.7%)" in out


def test_the_rendered_rate_is_a_fixed_format_not_a_float_repr() -> None:
    """Invariant 8: byte-identical output for the same input. 2/3 has no exact
    float, so an unformatted rate would print 0.6666666666666666 and a rounded
    one would depend on the platform's repr."""
    console = Console(width=120)
    with console.capture() as captured:
        render_coverage(
            Coverage(
                files_discovered=3,
                files_unreadable=0,
                files_with_errors=1,
                calls_resolved=2,
                calls_unresolved=1,
            ),
            console,
        )

    assert captured.get().strip() == (
        "Coverage: 2/3 files parsed (66.7%), 2/3 call sites resolved (66.7%)"
    )
