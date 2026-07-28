"""Declarative fixture expectations, per docs/22-testing section "The benchmark corpus".

A seeded fixture is a small Laravel project plus an `expected.yml` naming every finding
that must appear and every case that must stay silent. This module loads that file and
checks a scan of the fixture against it.

Three properties make the harness worth having over hand-written assertions:

* **`must_not_find` carries equal weight with `findings`.** A hit fails the run exactly as
  loudly as a missing finding. Precision is not observable in production - nobody files a
  bug for the finding that should never have fired - so it has to be gated here.
* **An undeclared finding fails too.** The file is a manifest of exactly what a scan
  produces, not a lower bound, so a rule that starts over-firing somewhere nobody thought
  to write a negative case for is still caught.
* **Every mismatch is reported, not just the first.** A rule change usually moves several
  findings at once, and seeing them together is what tells you whether the change was
  intended.

This is test infrastructure and lives under `tests/`, never under `src/`. Invariant 6 says
the shipped engine is complete offline and that argues against growing its dependency set;
the YAML parser is in the dev group for the same reason.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from vigilloo.graph import load_project
from vigilloo.models import Finding, PathStep
from vigilloo.rules import scan_project

EXPECTED_FILE = "expected.yml"

_TOP_KEYS = frozenset({"findings", "must_not_find"})
_FINDING_KEYS = frozenset({"rule", "file", "line", "severity", "path"})
_FINDING_REQUIRED = ("rule", "file", "line")
_STEP_KEYS = frozenset({"role", "symbol", "file", "line", "note"})
_FORBIDDEN_KEYS = frozenset({"rule", "file", "line", "reason"})

# A finding's identity for matching purposes: rule, file, line. Not Finding.id, which
# hashes every snippet on the path - an expectation file that had to carry a hash would be
# unreadable and unwritable by hand, and the point of the format is that a human reviews it.
Key = tuple[str, str, int]


@dataclass(frozen=True)
class ExpectedStep:
    """One declared step of an evidence path.

    `symbol` is matched as a substring of the step's snippet. `PathStep` carries the source
    text the developer wrote rather than a resolved callee FQN - Vigilloo does not resolve
    `orderByRaw` to `Illuminate\\Database\\Query\\Builder::orderByRaw`, because the builder
    lives in `vendor/` and is not scanned - so a substring of the snippet is the strongest
    check the model actually supports. `note` is matched the same way.
    """

    role: str
    symbol: str | None = None
    file: str | None = None
    line: int | None = None
    note: str | None = None


@dataclass(frozen=True)
class ExpectedFinding:
    """A finding that must appear, and optionally what its evidence path must look like."""

    rule: str
    file: str
    line: int
    severity: str | None = None
    path: tuple[ExpectedStep, ...] | None = None

    @property
    def key(self) -> Key:
        return (self.rule, self.file, self.line)


@dataclass(frozen=True)
class ForbiddenFinding:
    """A case that must stay silent.

    Every field given must match for the finding to count as a hit, so omitting `line`
    forbids a rule across a whole file and omitting `rule` forbids every rule at a location.
    `reason` is free text repeated back in the failure message: when a negative case starts
    firing, the first thing the reader needs is why it was ever expected to be quiet.
    """

    rule: str | None = None
    file: str | None = None
    line: int | None = None
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.rule is not None and finding.rule_id != self.rule:
            return False
        if self.file is not None and finding.span.file.as_posix() != self.file:
            return False
        return self.line is None or finding.span.start_line == self.line

    def describe(self) -> str:
        fields = [
            f"{name}={value}"
            for name, value in (("rule", self.rule), ("file", self.file), ("line", self.line))
            if value is not None
        ]
        return " ".join(fields)


@dataclass(frozen=True)
class Expectations:
    findings: tuple[ExpectedFinding, ...]
    must_not_find: tuple[ForbiddenFinding, ...]


class ExpectationError(ValueError):
    """The expectation file itself is malformed, as opposed to unsatisfied by a scan."""


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExpectationError(f"{where}: expected a mapping, got {type(value).__name__}")
    return value


def _sequence(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ExpectationError(f"{where}: expected a list, got {type(value).__name__}")
    return value


def _known_keys(entry: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    """Reject unrecognised keys.

    A misspelled key would otherwise be silently ignored, which turns a fixture that looks
    thoroughly specified into one that checks less than its author believed. Weakening an
    expectation must never be something a typo can do.
    """
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise ExpectationError(
            f"{where}: unknown key(s) {', '.join(unknown)}. Allowed: {', '.join(sorted(allowed))}"
        )


def _text(entry: dict[str, Any], key: str, where: str) -> str | None:
    value = entry.get(key)
    if value is None or isinstance(value, str):
        return value
    raise ExpectationError(f"{where}: {key} must be a string, got {type(value).__name__}")


def _number(entry: dict[str, Any], key: str, where: str) -> int | None:
    value = entry.get(key)
    if value is None or (isinstance(value, int) and not isinstance(value, bool)):
        return value
    raise ExpectationError(f"{where}: {key} must be an integer, got {type(value).__name__}")


def _step(raw: Any, where: str) -> ExpectedStep:
    entry = _mapping(raw, where)
    _known_keys(entry, _STEP_KEYS, where)
    role = _text(entry, "role", where)
    if not role:
        raise ExpectationError(f"{where}: a path step needs a role")
    return ExpectedStep(
        role=role,
        symbol=_text(entry, "symbol", where),
        file=_text(entry, "file", where),
        line=_number(entry, "line", where),
        note=_text(entry, "note", where),
    )


def _finding(raw: Any, where: str) -> ExpectedFinding:
    entry = _mapping(raw, where)
    _known_keys(entry, _FINDING_KEYS, where)
    missing = [key for key in _FINDING_REQUIRED if entry.get(key) is None]
    if missing:
        raise ExpectationError(f"{where}: missing required key(s) {', '.join(missing)}")

    rule = _text(entry, "rule", where)
    file = _text(entry, "file", where)
    line = _number(entry, "line", where)
    assert rule is not None and file is not None and line is not None  # checked above

    path = entry.get("path")
    steps = None
    if path is not None:
        raw_steps = _sequence(path, f"{where} path")
        if not raw_steps:
            raise ExpectationError(f"{where}: path is present but empty; omit it or declare it")
        steps = tuple(
            _step(step, f"{where} path step {number}")
            for number, step in enumerate(raw_steps, start=1)
        )

    return ExpectedFinding(
        rule=rule,
        file=file,
        line=line,
        severity=_text(entry, "severity", where),
        path=steps,
    )


def _forbidden(raw: Any, where: str) -> ForbiddenFinding:
    entry = _mapping(raw, where)
    _known_keys(entry, _FORBIDDEN_KEYS, where)
    forbidden = ForbiddenFinding(
        rule=_text(entry, "rule", where),
        file=_text(entry, "file", where),
        line=_number(entry, "line", where),
        reason=_text(entry, "reason", where) or "",
    )
    if forbidden.rule is None and forbidden.file is None and forbidden.line is None:
        # It would match every finding, so it would fail any fixture that finds anything.
        # Far more likely to be an unfinished entry than a deliberate "this tree is clean".
        raise ExpectationError(f"{where}: needs at least one of rule, file, line")
    return forbidden


def load_expectations(path: Path) -> Expectations:
    """Parse an `expected.yml`, rejecting anything it cannot check."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if document is None:
        raise ExpectationError(f"{path}: is empty")
    top = _mapping(document, str(path))
    _known_keys(top, _TOP_KEYS, str(path))

    findings = _sequence(top.get("findings") or [], f"{path} findings")
    forbidden = _sequence(top.get("must_not_find") or [], f"{path} must_not_find")
    return Expectations(
        findings=tuple(
            _finding(entry, f"{path} findings[{number}]") for number, entry in enumerate(findings)
        ),
        must_not_find=tuple(
            _forbidden(entry, f"{path} must_not_find[{number}]")
            for number, entry in enumerate(forbidden)
        ),
    )


def _key(finding: Finding) -> Key:
    return (finding.rule_id, finding.span.file.as_posix(), finding.span.start_line)


def _compare_path(
    where: str, expected: Sequence[ExpectedStep], actual: Sequence[PathStep]
) -> list[str]:
    """Check the declared steps against the real ones, in order and in full.

    The role sequence is compared as a whole rather than as a subsequence: a path that
    lost its `policy` step or grew a spurious one is a different explanation of the same
    finding, and invariant 2 makes the explanation the product. Nothing else in the format
    would notice.
    """
    expected_roles = [step.role for step in expected]
    actual_roles = [step.role for step in actual]
    if expected_roles != actual_roles:
        return [
            f"{where}: evidence path is {' -> '.join(actual_roles)}, "
            f"expected {' -> '.join(expected_roles)}"
        ]

    problems: list[str] = []
    for number, (want, got) in enumerate(zip(expected, actual, strict=True), start=1):
        label = f"{where}: step {number} ({want.role})"
        if want.symbol is not None and want.symbol not in got.snippet:
            problems.append(f"{label}: snippet {got.snippet!r} does not contain {want.symbol!r}")
        if want.file is not None and got.span.file.as_posix() != want.file:
            problems.append(f"{label}: is in {got.span.file.as_posix()}, expected {want.file}")
        if want.line is not None and got.span.start_line != want.line:
            problems.append(f"{label}: is at line {got.span.start_line}, expected {want.line}")
        if want.note is not None and want.note not in got.note:
            problems.append(f"{label}: note {got.note!r} does not contain {want.note!r}")
    return problems


def _compare(expected: ExpectedFinding, actual: Finding) -> list[str]:
    where = f"{expected.rule} at {expected.file}:{expected.line}"
    problems: list[str] = []
    if expected.severity is not None and actual.severity != expected.severity:
        problems.append(f"{where}: severity is {actual.severity}, expected {expected.severity}")
    if expected.path is not None:
        problems.extend(_compare_path(where, expected.path, actual.evidence_path))
    return problems


def verify(findings: Iterable[Finding], expectations: Expectations) -> list[str]:
    """Every way the scan disagrees with the expectations, as human-readable lines.

    An empty list means the fixture is satisfied.
    """
    unclaimed: dict[Key, list[Finding]] = {}
    ordered: list[Finding] = list(findings)
    for finding in ordered:
        unclaimed.setdefault(_key(finding), []).append(finding)

    problems: list[str] = []
    for expected in expectations.findings:
        bucket = unclaimed.get(expected.key)
        if not bucket:
            problems.append(f"missing finding: {expected.rule} at {expected.file}:{expected.line}")
            continue
        problems.extend(_compare(expected, bucket.pop(0)))

    for bucket in unclaimed.values():
        for finding in bucket:
            problems.append(
                f"undeclared finding: {finding.rule_id} at "
                f"{finding.span.file.as_posix()}:{finding.span.start_line}. "
                "Add it to findings: if it is correct, or to must_not_find: if it is not"
            )

    for forbidden in expectations.must_not_find:
        for finding in ordered:
            if forbidden.matches(finding):
                reason = f" ({forbidden.reason})" if forbidden.reason else ""
                problems.append(
                    f"must_not_find hit: {finding.rule_id} at "
                    f"{finding.span.file.as_posix()}:{finding.span.start_line} "
                    f"matches must_not_find [{forbidden.describe()}]{reason}"
                )
    return problems


def scan_fixture(root: Path) -> list[Finding]:
    """The findings a fixture produces, by the same path `vigilloo scan` takes."""
    return scan_project(load_project(root))


def assert_fixture(root: Path) -> None:
    """Scan `root` and raise AssertionError naming every unmet expectation."""
    expected_path = root / EXPECTED_FILE
    problems = verify(scan_fixture(root), load_expectations(expected_path))
    if problems:
        listed = "\n".join(f"  - {problem}" for problem in problems)
        raise AssertionError(f"{expected_path} is not satisfied:\n{listed}")


def discover(root: Path) -> list[Path]:
    """Every fixture directory under `root`, in a stable order."""
    return sorted(found.parent for found in root.rglob(EXPECTED_FILE))
