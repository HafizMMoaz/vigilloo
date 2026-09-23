"""Tests for dependency advisory loading and version constraint matching."""

from unittest.mock import patch

from vigilloo.deps.advisories import (
    load_advisories,
    match_package_advisories,
    matches_constraint,
)
from vigilloo.deps.lockfile import Package


def test_matches_constraint_relational() -> None:
    assert matches_constraint("7.4.4", "<7.4.5")
    assert not matches_constraint("7.4.5", "<7.4.5")
    assert matches_constraint("7.4.5", "<=7.4.5")
    assert matches_constraint("7.0.0", ">=7.0.0")
    assert not matches_constraint("6.9.9", ">=7.0.0")
    assert matches_constraint("8.0.1", ">8.0.0")


def test_matches_constraint_range_and_or() -> None:
    # Range with comma (AND)
    assert matches_constraint("7.4.0", ">=7.0.0,<7.4.5")
    assert not matches_constraint("7.4.5", ">=7.0.0,<7.4.5")
    assert not matches_constraint("6.5.0", ">=7.0.0,<7.4.5")

    # Disjunction with || (OR)
    rule = "<6.5.8 || >=7.0.0,<7.4.5"
    assert matches_constraint("6.5.7", rule)
    assert not matches_constraint("6.5.8", rule)
    assert matches_constraint("7.1.0", rule)
    assert not matches_constraint("7.4.5", rule)
    assert not matches_constraint("7.5.0", rule)


def test_matches_constraint_caret_and_tilde() -> None:
    assert matches_constraint("1.2.5", "^1.2.0")
    assert matches_constraint("1.9.9", "^1.2.0")
    assert not matches_constraint("2.0.0", "^1.2.0")
    assert not matches_constraint("1.1.9", "^1.2.0")

    assert matches_constraint("1.2.5", "~1.2.0")
    assert not matches_constraint("1.3.0", "~1.2.0")


def test_matches_constraint_wildcard() -> None:
    assert matches_constraint("1.2.3", "1.2.*")
    assert not matches_constraint("1.3.0", "1.2.*")


def test_load_advisories_offline() -> None:
    # Verify zero network socket calls during loading
    with patch("socket.socket", side_effect=RuntimeError("Network access forbidden")):
        advisories = load_advisories()
        assert len(advisories) >= 5

        # Check essential fields on every advisory
        for adv in advisories:
            assert adv.id
            assert adv.package_name
            assert adv.affected_range
            assert adv.severity in ("critical", "high", "medium", "low")


def test_match_package_advisories() -> None:
    advisories = load_advisories()
    vulnerable_pkg = Package(
        name="guzzlehttp/guzzle",
        version="7.4.4",
        raw_version="7.4.4",
        is_dev=False,
    )
    safe_pkg = Package(
        name="guzzlehttp/guzzle",
        version="7.4.5",
        raw_version="7.4.5",
        is_dev=False,
    )

    vuln_matches = match_package_advisories(vulnerable_pkg, advisories)
    assert len(vuln_matches) >= 1
    assert any(a.cve == "CVE-2022-31090" for a in vuln_matches)

    safe_matches = match_package_advisories(safe_pkg, advisories)
    assert len(safe_matches) == 0
