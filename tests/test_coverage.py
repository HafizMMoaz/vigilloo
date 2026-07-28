"""Invariant 4: coverage is reported, never hidden.

A clean result over a codebase 40% of which failed to parse is a lie, so the
fraction is measured rather than described, and these tests are what keep the
measurement honest. The rates are gated in CI by docs/22-testing section
"Metrics gated in CI".
"""

import shutil
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.graph import coverage, load_project
from vigilloo.models import Coverage, ParseFailure, WalkStats
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


def test_the_scan_names_the_construct_that_failed_to_parse() -> None:
    """TASK-031: the parse rate points at a cause, not only at a filename.

    Measured over the whole scan rather than over the parser alone, because the
    detail is only useful if it survives to the record the report reads.
    """
    result = _scan(BROKEN)

    assert [f.label for f in result.parse_failures] == [
        "method ReportController::index (app/Http/Controllers/ReportController.php)"
    ]


def test_naming_the_constructs_does_not_move_the_parse_rate() -> None:
    """The gate in tests/test_coverage_gates.py divides by files, and must stay
    doing so. One file with four broken methods is one file, not four."""
    result = _scan(BROKEN)

    assert result.files_with_errors == 1
    assert result.parse_success_rate == 2 / 3
    assert len({f.file for f in result.parse_failures}) == result.files_with_errors


def test_a_clean_project_collects_no_failure_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A project that parses pays nothing for this feature.

    `load_project` must consult `has_errors` before it asks for the detail, so a
    codebase with ten thousand healthy files never walks one of them looking for
    errors it already knows are absent.
    """

    def explode(parsed: object) -> None:
        raise AssertionError("a clean file must not be inspected for parse failures")

    monkeypatch.setattr("vigilloo.graph.error_constructs", explode)
    stats = WalkStats()
    project = load_project(FIXTURE, stats)

    assert project.parse_failures == []
    assert coverage(project, stats).parse_failures == ()


def test_the_construct_detail_is_printed_with_the_rates() -> None:
    console = Console(width=200)
    with console.capture() as captured:
        render_coverage(
            Coverage(
                files_discovered=2,
                files_unreadable=0,
                files_with_errors=1,
                calls_resolved=1,
                calls_unresolved=0,
                parse_failures=(
                    ParseFailure(
                        Path("app/Http/Controllers/OrderController.php"), "method", "O::s"
                    ),
                    ParseFailure(Path("app/helpers.php"), "file", ""),
                ),
            ),
            console,
        )

    assert captured.get().strip().splitlines()[1] == (
        "Parse errors in: method O::s (app/Http/Controllers/OrderController.php); "
        "app/helpers.php (top level)"
    )


def test_hundreds_of_failures_are_capped_and_counted() -> None:
    """The coverage block stays readable on a project that is broadly broken.

    A scan of a codebase parsed with the wrong PHP version fails in every file,
    and a coverage block that prints all of them buries the findings under
    itself. The remainder is stated so the cap cannot be misread as the total.
    """
    console = Console(width=400)
    failures = tuple(
        ParseFailure(Path(f"app/C{n:03d}.php"), "method", f"C{n:03d}::handle") for n in range(40)
    )
    with console.capture() as captured:
        render_coverage(
            Coverage(
                files_discovered=40,
                files_unreadable=0,
                files_with_errors=40,
                calls_resolved=0,
                calls_unresolved=0,
                parse_failures=failures,
            ),
            console,
        )

    printed = captured.get().strip().splitlines()[1]
    assert printed.count(";") == 4  # five named
    assert printed.endswith("and 35 more")
