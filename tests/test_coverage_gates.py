"""The two leading indicators, gated: docs/22-testing section "Metrics gated in CI".

`tests/test_coverage.py` proves the two rates are *measured* correctly, including that they
can fall. This file is the other half: it proves they have not *fallen*, and it is the only
thing that turns the measurement into a build failure. Delete it and coverage becomes a
number printed in a report that nobody has to keep true - parse success could slide from
100% to 60% over a dozen parser changes and every build would stay green, because the rate
would still be reported accurately and reported accurately is all the other file asks.

The resolution rate matters most, and matters first. Unresolved calls are where false
negatives hide, and a false negative is invisible in production: nobody files a bug for the
vulnerability that was never reported. The rate moves the moment the walk stops following a
construct, which is one refactor before the findings that used to depend on it disappear.

**Which corpus the gate runs over, and why.** Only `tests/fixtures/laravel-minimal`, and
that is deliberate rather than an oversight: `tests/fixtures/laravel-unparseable` contains a
file that does not parse *on purpose* (2 of its 3 files parse, so it scores 66.7%), and its
whole reason for existing is to keep one measurement below 100% so a working metric can be
told from a constant. Gating it would leave two options, both bad - fail the build forever,
or drop the parse floor to something that clears 66.7% and therefore gates nothing at all.
So it is excluded from the gate and asserted separately below, which also catches the case
docs/22-testing warns about: somebody "fixing" its syntax and silently disabling it.

The gate is applied per fixture rather than to corpus-wide totals. It is the stricter of the
two readings - if every fixture individually clears the floor then the pooled ratio does too,
being a weighted average of numbers each at or above it - and when it fails it names the
fixture instead of reporting that the corpus as a whole slipped.

Measured on the day this landed, so a future reader can see how much headroom there was:
laravel-minimal parses 16/16 files (100.0%) and resolves 52/52 attempts (100.0%). Both
floors are cleared outright, so nothing here is xfail and nothing is asserting a rate the
engine cannot currently reach.
"""

from pathlib import Path

import pytest

from vigilloo.graph import coverage, load_project
from vigilloo.models import Coverage, WalkStats
from vigilloo.rules import scan_project

# docs/22-testing section "Metrics gated in CI". These are the spec's numbers, copied and
# not negotiated: a threshold that gets lowered whenever it fails is a comment, not a gate.
# Raising one is fine and expected; lowering one is a spec change and belongs in that
# document first.
PARSE_SUCCESS_FLOOR = 0.995
CALL_RESOLUTION_FLOOR = 0.85

GATED_CORPUS = (Path("tests/fixtures/laravel-minimal"),)

# Deliberately below the parse floor. See the module docstring.
UNGATED = Path("tests/fixtures/laravel-unparseable")


def _measure(root: Path) -> Coverage:
    """Coverage for a full scan of `root`, by the same path `vigilloo scan` takes.

    The rules run, not just the graph load: a good part of the resolution attempts are made
    by the taint walk following a route into a controller and a call into its callee, so
    measuring after `load_project` alone would gate a fraction of the number the report
    prints and quietly stop covering the walk.
    """
    stats = WalkStats()
    project = load_project(root, stats)
    scan_project(project, stats)
    return coverage(project, stats)


@pytest.mark.parametrize("root", GATED_CORPUS, ids=lambda root: root.name)
def test_parse_success_rate_clears_the_gate(root: Path) -> None:
    result = _measure(root)

    assert result.parse_success_rate >= PARSE_SUCCESS_FLOOR, (
        f"{root}: parse success {result.parse_success_rate:.1%} "
        f"({result.files_parsed}/{result.files_discovered}) is below the "
        f"{PARSE_SUCCESS_FLOOR:.1%} floor in docs/22-testing"
    )


@pytest.mark.parametrize("root", GATED_CORPUS, ids=lambda root: root.name)
def test_call_resolution_rate_clears_the_gate(root: Path) -> None:
    """The leading indicator. This is the one that goes red first."""
    result = _measure(root)

    assert result.call_resolution_rate >= CALL_RESOLUTION_FLOOR, (
        f"{root}: call resolution {result.call_resolution_rate:.1%} "
        f"({result.calls_resolved}/{result.calls_attempted}) is below the "
        f"{CALL_RESOLUTION_FLOOR:.1%} floor in docs/22-testing. Unresolved calls are where "
        "false negatives hide, so this moves before any finding is lost"
    )


@pytest.mark.parametrize("root", GATED_CORPUS, ids=lambda root: root.name)
def test_the_gate_has_something_to_divide_by(root: Path) -> None:
    """A vacuous 100% must not be able to pass the gate.

    Zero attempts is defined as 1.0 for both rates, which is right for a report - a project
    with no PHP in it hid nothing - and dangerous for a gate, because a fixture that stopped
    being discovered, or a walk that stopped attempting anything at all, would clear both
    floors while measuring nothing. The two tests above cannot tell that apart from a
    perfect scan; this one can.
    """
    result = _measure(root)

    assert result.files_discovered > 0, f"{root}: no files discovered, so the rates are vacuous"
    assert result.calls_attempted > 0, f"{root}: nothing was resolved or failed to resolve"


def test_the_gate_fails_when_a_rate_is_below_the_floor() -> None:
    """A gate that cannot fail is not a gate.

    The comparison is `>=` against a float that is 1.0 today for both rates, so a flipped
    operator or a threshold read as a percentage rather than a fraction would still pass
    every case above. Pinned against constructed counts, since the fixtures deliberately
    have no way to produce a rate in the failing band.
    """
    bad_parse = Coverage(
        files_discovered=1000,
        files_unreadable=0,
        files_with_errors=6,  # 99.4%, just under the floor
        calls_resolved=1,
        calls_unresolved=0,
    )
    bad_resolution = Coverage(
        files_discovered=1,
        files_unreadable=0,
        files_with_errors=0,
        calls_resolved=84,
        calls_unresolved=16,  # 84%, just under the floor
    )

    assert bad_parse.parse_success_rate < PARSE_SUCCESS_FLOOR
    assert bad_resolution.call_resolution_rate < CALL_RESOLUTION_FLOOR


def test_the_ungated_fixture_is_still_the_one_below_the_floor() -> None:
    """Why laravel-unparseable is not in GATED_CORPUS, asserted instead of asserted-by-comment.

    docs/22-testing: "fixing its syntax silently disables the test". It would also silently
    make this exclusion look arbitrary to whoever reads the list next. If the broken file
    ever parses, this fails and says so, and the fixture can then be moved into the gate on
    purpose rather than by drift.
    """
    result = _measure(UNGATED)

    assert result.parse_success_rate < PARSE_SUCCESS_FLOOR, (
        f"{UNGATED} now parses cleanly ({result.files_parsed}/{result.files_discovered}). "
        "Its unparseable file is deliberate; restore it, or move the fixture into "
        "GATED_CORPUS deliberately"
    )
    # Its resolution rate is not the reason it is excluded, and it clears the floor today.
    assert result.call_resolution_rate >= CALL_RESOLUTION_FLOOR
