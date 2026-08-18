"""Every seeded fixture, checked against its own expected.yml.

Two things are being tested here. The first is the fixtures: `test_fixture_matches_its_manifest`
is the whole benchmark gate from docs/22-testing, and adding a fixture directory with an
`expected.yml` is all it takes to enrol in it.

The second is the harness itself. A test harness that cannot fail is not a test harness, and
this one is now the only thing standing between a broken rule and a green build, so each way it
is supposed to fail gets its own case below - built by handing a deliberately wrong manifest to
a fixture whose real findings are known.
"""

from pathlib import Path

import pytest
from harness import EXPECTED_FILE, ExpectationError, assert_fixture, discover

TESTS = Path("tests")
FIXTURES = discover(TESTS)


def test_at_least_one_fixture_is_enrolled() -> None:
    """An empty parametrisation passes silently, which would retire the gate by accident."""
    assert FIXTURES


@pytest.mark.parametrize("root", FIXTURES, ids=lambda root: root.name)
def test_fixture_matches_its_manifest(root: Path) -> None:
    assert_fixture(root)


# --- The harness tests itself ----------------------------------------------------------
#
# A tiny project of its own rather than a copy of laravel-minimal: these cases are about the
# checker, and pinning them to another fixture's line numbers would make them fail whenever
# that fixture is edited, for reasons that have nothing to do with the harness.

_ROUTES = """<?php

use App\\Http\\Controllers\\ThingController;
use Illuminate\\Support\\Facades\\Route;

Route::post('/things', [ThingController::class, 'store']);
"""

_CONTROLLER = """<?php

namespace App\\Http\\Controllers;

use App\\Models\\Thing;
use Illuminate\\Http\\Request;

class ThingController
{
    public function store(Request $request)
    {
        return Thing::create($request->all());
    }
}
"""

_MODEL = """<?php

namespace App\\Models;

class Thing extends Model
{
    protected $guarded = [];
}
"""

# The one finding the project above produces, spelled correctly.
_TRUE_MANIFEST = """
findings:
  - rule: laravel.mass-assignment
    file: app/Http/Controllers/ThingController.php
    line: 12
    severity: high
    path:
      - role: entry
      - role: source
      - role: model
      - role: sink
  - rule: laravel.unauthenticated-route
    file: routes/api.php
    line: 6
    severity: high
    path:
      - role: gap
"""


@pytest.fixture(scope="module")
def one_finding_project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("one-finding")
    for relative, source in (
        ("routes/api.php", _ROUTES),
        ("app/Http/Controllers/ThingController.php", _CONTROLLER),
        ("app/Models/Thing.php", _MODEL),
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    return root


def _check(root: Path, manifest: str) -> None:
    (root / EXPECTED_FILE).write_text(manifest)
    assert_fixture(root)


def test_a_correct_manifest_passes(one_finding_project: Path) -> None:
    """The control. Without it, every case below could be passing for the wrong reason."""
    _check(one_finding_project, _TRUE_MANIFEST)


def test_a_missing_finding_fails(one_finding_project: Path) -> None:
    manifest = (
        _TRUE_MANIFEST
        + """
  - rule: php.sql-injection
    file: app/Repositories/Nowhere.php
    line: 3
"""
    )
    with pytest.raises(AssertionError, match="missing finding: php.sql-injection"):
        _check(one_finding_project, manifest)


def test_a_must_not_find_hit_fails(one_finding_project: Path) -> None:
    """The case the whole format exists for: a rule firing where it was promised not to."""
    manifest = (
        _TRUE_MANIFEST
        + """
must_not_find:
  - rule: laravel.mass-assignment
    file: app/Http/Controllers/ThingController.php
    reason: deliberately wrong
"""
    )
    with pytest.raises(AssertionError, match="must_not_find hit: laravel.mass-assignment"):
        _check(one_finding_project, manifest)


def test_an_undeclared_finding_fails(one_finding_project: Path) -> None:
    """The manifest is exhaustive, so a new finding fails even with no negative case for it."""
    with pytest.raises(AssertionError, match="undeclared finding: laravel.mass-assignment"):
        _check(one_finding_project, "findings: []\n")


def test_a_wrong_severity_fails(one_finding_project: Path) -> None:
    manifest = _TRUE_MANIFEST.replace("severity: high", "severity: low")
    with pytest.raises(AssertionError, match="severity is high, expected low"):
        _check(one_finding_project, manifest)


def test_a_wrong_evidence_path_fails(one_finding_project: Path) -> None:
    """Invariant 2 makes the path the product, so a path that changed shape is a failure."""
    manifest = _TRUE_MANIFEST.replace("      - role: model\n", "")
    with pytest.raises(AssertionError, match="evidence path is entry -> source -> model -> sink"):
        _check(one_finding_project, manifest)


def test_a_wrong_step_symbol_fails(one_finding_project: Path) -> None:
    manifest = _TRUE_MANIFEST.replace(
        "      - role: sink\n", "      - role: sink\n        symbol: 'Thing::forceFill'\n"
    )
    with pytest.raises(AssertionError, match="does not contain 'Thing::forceFill'"):
        _check(one_finding_project, manifest)


def test_a_wrong_step_line_fails(one_finding_project: Path) -> None:
    manifest = _TRUE_MANIFEST.replace(
        "      - role: model\n", "      - role: model\n        line: 99\n"
    )
    with pytest.raises(AssertionError, match="is at line 7, expected 99"):
        _check(one_finding_project, manifest)


def test_an_unknown_key_is_rejected(one_finding_project: Path) -> None:
    """A typo must never be able to quietly weaken a manifest."""
    manifest = _TRUE_MANIFEST.replace("    severity: high\n", "    serverity: high\n")
    with pytest.raises(ExpectationError, match="unknown key\\(s\\) serverity"):
        _check(one_finding_project, manifest)


def test_a_must_not_find_with_no_fields_is_rejected(one_finding_project: Path) -> None:
    """It would forbid every finding, so it is an unfinished entry, not a strict one."""
    manifest = _TRUE_MANIFEST + "must_not_find:\n  - reason: forgot to say what\n"
    with pytest.raises(ExpectationError, match="at least one of rule, file, line"):
        _check(one_finding_project, manifest)
