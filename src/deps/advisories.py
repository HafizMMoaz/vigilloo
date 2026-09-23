"""Offline security advisory database and version constraint matching."""

import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .lockfile import Package


@dataclass(frozen=True)
class Advisory:
    """Security vulnerability advisory affecting a dependency."""

    id: str
    package_name: str
    affected_range: str
    fixed_version: str | None
    severity: str
    summary: str
    cve: str | None = None
    cvss: float | None = None
    cwe: str | None = None
    functions: tuple[str, ...] = ()


def _parse_version(v: str) -> tuple[int, int, int, int]:
    """Parse a version string into a comparable (major, minor, patch, prerelease_flag) tuple."""
    v = v.lstrip("vV").strip()
    # Separate pre-release tag like -beta1, -dev, .x-dev
    prerelease = 0
    if "-" in v:
        v, _ = v.split("-", 1)
        prerelease = -1

    parts = []
    for piece in v.split("."):
        # Extract leading numeric digits
        m = re.match(r"^(\d+)", piece)
        if m:
            parts.append(int(m.group(1)))
        else:
            parts.append(0)

    while len(parts) < 3:
        parts.append(0)

    return (parts[0], parts[1], parts[2], prerelease)


def _compare_versions(v1: str, op: str, v2: str) -> bool:
    """Compare two version strings with a standard operator (<, <=, >, >=, ==, !=)."""
    p1 = _parse_version(v1)
    p2 = _parse_version(v2)

    # When comparing against an upper bound with pre-release, normalise prerelease
    # for strict version comparisons (e.g. 7.4.5 vs 7.4.5)
    t1 = p1[:3]
    t2 = p2[:3]

    if op == "<":
        return t1 < t2 or (t1 == t2 and p1[3] < p2[3])
    if op == "<=":
        return t1 < t2 or (t1 == t2 and p1[3] <= p2[3])
    if op == ">":
        return t1 > t2 or (t1 == t2 and p1[3] > p2[3])
    if op == ">=":
        return t1 > t2 or (t1 == t2 and p1[3] >= p2[3])
    if op in ("==", "="):
        return t1 == t2 and p1[3] == p2[3]
    if op == "!=":
        return t1 != t2 or p1[3] != p2[3]
    return False


def _eval_single_clause(version: str, clause: str) -> bool:
    """Evaluate a single constraint clause against a version."""
    clause = clause.strip()
    if not clause or clause == "*":
        return True

    # Caret constraint ^X.Y.Z
    if clause.startswith("^"):
        base_v = clause[1:].strip()
        maj, min_, patch, _ = _parse_version(base_v)
        if maj > 0:
            next_v = f"{maj + 1}.0.0"
        elif min_ > 0:
            next_v = f"0.{min_ + 1}.0"
        else:
            next_v = f"0.0.{patch + 1}"
        return _compare_versions(version, ">=", base_v) and _compare_versions(version, "<", next_v)

    # Tilde constraint ~X.Y.Z
    if clause.startswith("~"):
        base_v = clause[1:].strip()
        maj, min_, _, _ = _parse_version(base_v)
        next_v = f"{maj}.{min_ + 1}.0"
        return _compare_versions(version, ">=", base_v) and _compare_versions(version, "<", next_v)

    # Wildcard constraint X.Y.*
    if ".*" in clause:
        prefix = clause.replace(".*", "")
        maj, min_, _, _ = _parse_version(prefix)
        base_v = f"{maj}.{min_}.0"
        next_v = f"{maj}.{min_ + 1}.0"
        return _compare_versions(version, ">=", base_v) and _compare_versions(version, "<", next_v)

    # Relational operators
    for op in ("<=", ">=", "!=", "==", "<", ">", "="):
        if clause.startswith(op):
            target = clause[len(op) :].strip()
            return _compare_versions(version, op, target)

    # Bare version implies equality
    return _compare_versions(version, "==", clause)


def matches_constraint(version: str, constraint: str) -> bool:
    """Check if a version matches a Composer/SemVer constraint string.

    Supports || (OR), comma / space (AND), relational ops, ^ and ~.
    """
    if not constraint or constraint == "*":
        return True

    # Split by OR (||)
    or_branches = [b.strip() for b in constraint.split("||") if b.strip()]
    for branch in or_branches:
        # Split by comma or space for AND
        clauses = re.split(r"[, ]+", branch)
        branch_matches = True
        for c in clauses:
            c = c.strip()
            if not c:
                continue
            if not _eval_single_clause(version, c):
                branch_matches = False
                break
        if branch_matches:
            return True

    return False


def load_advisories() -> list[Advisory]:
    """Load offline vendored security advisories from package data."""
    data_path = Path(__file__).parent / "data" / "advisories.json"
    if not data_path.exists():
        res_file = resources.files("vigilloo.deps.data").joinpath("advisories.json")
        with res_file.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    else:
        raw = json.loads(data_path.read_text(encoding="utf-8"))

    advisories: list[Advisory] = []
    for item in raw:
        advisories.append(
            Advisory(
                id=item["id"],
                cve=item.get("cve"),
                package_name=item["package_name"].lower(),
                affected_range=item["affected_range"],
                fixed_version=item.get("fixed_version"),
                severity=item.get("severity", "medium").lower(),
                cvss=float(item["cvss"]) if "cvss" in item and item["cvss"] is not None else None,
                cwe=item.get("cwe"),
                summary=item.get("summary", ""),
                functions=tuple(item.get("functions", ())),
            )
        )
    return advisories


def match_package_advisories(package: Package, advisories: list[Advisory]) -> list[Advisory]:
    """Find all advisories that match the installed package and version."""
    matches: list[Advisory] = []
    pkg_name = package.name.lower()
    for adv in advisories:
        if adv.package_name == pkg_name:
            if matches_constraint(package.version, adv.affected_range):
                matches.append(adv)
    return matches
