# Task 9: The Corpus and the Precision Harness

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** `scripts/corpus.py report` prints a per-rule precision table and a drift report over
pinned real Laravel applications, so the false-positive rate of the 32 registered rules stops
being unknown.

**Architecture:** Real applications are enrolled as git submodules pinned to a commit, never
vendored. Each application gets a committed `corpus/triage/<app>.yml` keyed by finding
fingerprint, holding a three-state verdict per finding. Precision is counted over reviewed
verdicts; drift is a set difference between a fresh scan's fingerprints and the triage file's.
The set-difference logic lives in `src/baseline.py` because `vigilloo baseline` (Task 13) needs
the same primitive; everything else is dev tooling in `scripts/corpus.py`.

**Tech Stack:** Python 3.13+, uv, PyYAML (already a dependency, `>=6.0,<6.1`), pytest, ruff,
mypy, git submodules, GitHub Actions.

**Spec:** [2026-08-20-task-9-corpus-design.md](2026-08-20-task-9-corpus-design.md). Where this
plan and that design disagree, the design wins.

## Global Constraints

- **Invariant 3.** Triage is keyed by the location-independent `fingerprint`, never by file and
  line. A location key orphans every verdict the first time an upstream commit adds an import.
- **Invariant 4.** Coverage is reported, never hidden. A scan whose parse rate is below floor is
  a failure, not a clean result.
- **Invariant 8, determinism.** Every generated file and every selection order is sorted and
  stable across runs.
- **A failed scan must never be counted as a clean one.** A crash, timeout or OOM produces a
  hard failure, never an empty report. An empty report scores 100% precision.
- **Applications are submodules, never copied into the tree.** Monica is AGPL-3.0 and this
  repository is proprietary. Do not "simplify" a submodule into a vendored directory.
- **No em dashes** in code, comments, docstrings, docs or commit messages. Use a hyphen.
- **Imports inside `src/` are relative.** `from .models import Finding`, never
  `from vigilloo.models import Finding`.
- **No shell heredocs.** They hang this environment's shell. Write files with the file-write
  tool.
- **Never add Claude as a co-author** on any commit or PR.
- Four gates must pass before each commit: `uv run pytest`, `uv run ruff format --check .`,
  `uv run ruff check`, `uv run mypy`.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/baseline.py` | `FingerprintDiff` and `diff_fingerprints()`. Pure, no I/O. Shared with Task 13 |
| `scripts/corpus.py` | CLI: `scan`, `triage`, `report`. Orchestration, verdict I/O, precision counting, table rendering |
| `tests/test_baseline.py` | Unit tests for the set diff |
| `tests/test_corpus_precision.py` | Precision maths, quota selection, and harness-can-fail cases |
| `corpus/pins.yml` | One entry per enrolled app: SHA, Laravel version, PHP version, file count, LOC, rationale |
| `corpus/triage/<app>.yml` | Committed verdicts, keyed by fingerprint |
| `corpus/reports/` | Gitignored. Raw `--format json` output |
| `.github/workflows/corpus-nightly.yml` | Nightly full corpus run |

`scripts/corpus.py` prints, so it needs a `T20` per-file-ignore alongside `dump_ast.py` and
`debt.py`. It is also added to mypy's `files`, because it computes the ship-gate number.

## Reference: the real JSON shape

Confirmed against `uv run vigilloo scan tests/fixtures/laravel-minimal --format json` on
`main` at `9d911d4`. Do not guess these keys:

```
top level:  coverage, findings, schema_version, summary, tool
tool:       name, version, ruleset_hash          (ruleset_hash is 16 hex chars)
coverage:   files_discovered, files_parsed, files_with_errors, files_unreadable,
            parse_failures, parse_success_rate, calls_attempted, calls_resolved,
            calls_unresolved, call_resolution_rate
finding:    id, fingerprint, rule_id, severity, title, cwe, location,
            evidence_path, alternative_paths, remediation, needs_review
location:   file, start_line, start_col, end_line, end_col
```

`id` and `fingerprint` are both 16 lowercase hex characters. `id` changes when code moves;
`fingerprint` does not. **Triage keys on `fingerprint`.**

---

### Task 9a: The fingerprint set diff

`src/baseline.py`. Pure and typed, because Task 13's `vigilloo baseline` consumes it and because
mypy covers `src` only.

**Files:**
- Create: `src/baseline.py`
- Test: `tests/test_baseline.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `FingerprintDiff` (frozen dataclass, fields `added: tuple[str, ...]`,
  `removed: tuple[str, ...]`, `unchanged: tuple[str, ...]`) and
  `diff_fingerprints(current: Iterable[str], approved: Iterable[str]) -> FingerprintDiff`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_baseline.py`:

```python
"""The fingerprint set diff that drift detection and `vigilloo baseline` both read.

Every assertion here is about ordering as much as membership: a diff whose output order
depends on set iteration would make two runs over unchanged code produce different reports,
which is invariant 8.
"""

from vigilloo.baseline import diff_fingerprints


def test_added_removed_and_unchanged_are_partitioned() -> None:
    diff = diff_fingerprints(current=["aaa", "bbb"], approved=["bbb", "ccc"])
    assert diff.added == ("aaa",)
    assert diff.removed == ("ccc",)
    assert diff.unchanged == ("bbb",)


def test_output_is_sorted_regardless_of_input_order() -> None:
    """Invariant 8: set iteration order must not reach the report."""
    forward = diff_fingerprints(current=["ccc", "aaa", "bbb"], approved=[])
    backward = diff_fingerprints(current=["bbb", "ccc", "aaa"], approved=[])
    assert forward.added == ("aaa", "bbb", "ccc")
    assert forward == backward


def test_duplicate_fingerprints_collapse() -> None:
    """Two findings can share a fingerprint; the set is of fingerprints, not findings."""
    diff = diff_fingerprints(current=["aaa", "aaa"], approved=[])
    assert diff.added == ("aaa",)


def test_empty_current_reports_everything_removed() -> None:
    """A scan that suddenly finds nothing is drift, never a clean result."""
    diff = diff_fingerprints(current=[], approved=["aaa", "bbb"])
    assert diff.removed == ("aaa", "bbb")
    assert diff.added == ()


def test_no_change_is_all_unchanged() -> None:
    diff = diff_fingerprints(current=["aaa"], approved=["aaa"])
    assert diff == diff_fingerprints(current=["aaa"], approved=["aaa"])
    assert diff.added == () and diff.removed == ()
    assert diff.unchanged == ("aaa",)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_baseline.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'vigilloo.baseline'`

- [ ] **Step 3: Write the implementation**

Create `src/baseline.py`:

```python
"""Set difference over finding fingerprints.

Drift detection in the corpus harness and `vigilloo baseline` (Task 13) ask the same
question: which findings are new, which are gone, which persist. Answering it in one place
means there is one definition of "the same finding" rather than two that disagree.

Fingerprints rather than ids, deliberately. A fingerprint is location-independent
(invariant 3), so reformatting a file or pulling an upstream commit does not make an
unchanged finding look new.
"""

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class FingerprintDiff:
    """Three disjoint, sorted partitions of two fingerprint sets."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    unchanged: tuple[str, ...]


def diff_fingerprints(current: Iterable[str], approved: Iterable[str]) -> FingerprintDiff:
    """Partition `current` against `approved`.

    Output is sorted, not set-ordered. Python set iteration order is stable within a
    process but is not a documented ordering, and letting it reach the report would break
    invariant 8 in a way that reproduces only intermittently.
    """
    current_set = set(current)
    approved_set = set(approved)
    return FingerprintDiff(
        added=tuple(sorted(current_set - approved_set)),
        removed=tuple(sorted(approved_set - current_set)),
        unchanged=tuple(sorted(current_set & approved_set)),
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_baseline.py -v`
Expected: 5 passed

- [ ] **Step 5: Run the four gates**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
```

- [ ] **Step 6: Commit**

```bash
git add src/baseline.py tests/test_baseline.py
git commit -m "feat: add the fingerprint set diff shared by drift and baseline"
```

---

### Task 9b: Corpus scaffolding and the first submodule

Enrols `laravel/laravel` first: it is the clean-run control from the parent plan, it is small
enough to sit on the PR critical path, and it makes the harness testable before any large
application is involved.

**Files:**
- Create: `corpus/pins.yml`
- Create: `corpus/triage/.gitkeep`
- Modify: `.gitignore`
- Modify: `.gitmodules` (created by `git submodule add`)

**Interfaces:**
- Produces: `corpus/pins.yml` with the schema below, read by Task 9c.

- [ ] **Step 1: Add the submodule**

```bash
git submodule add https://github.com/laravel/laravel.git corpus/laravel-skeleton
```

- [ ] **Step 2: Pin it to a Laravel 9-11 commit**

The pin policy is the newest commit still declaring `^9`, `^10` or `^11` for
`laravel/framework`. Find it:

```bash
git -C corpus/laravel-skeleton log --format='%H' -- composer.json | while read sha; do
  ver=$(git -C corpus/laravel-skeleton show "$sha:composer.json" | python3 -c "import json,sys; print(json.load(sys.stdin)['require'].get('laravel/framework','NONE'))")
  case "$ver" in ^9.*|^10.*|^11.*) echo "$sha $ver"; break;; esac
done
```

Check that commit out inside the submodule and stage the new pointer:

```bash
git -C corpus/laravel-skeleton checkout <sha-from-above>
git add corpus/laravel-skeleton
```

- [ ] **Step 3: Record the pin and its rationale**

Create `corpus/pins.yml`. Fill the numeric fields from the commands in the comments; do not
invent them:

```yaml
# One entry per enrolled application.
#
# A pin with no recorded rationale cannot be audited. When v1.0 widens the target beyond
# Laravel 9-11, whoever re-pins needs to know why each SHA was chosen.
#
# php_files: find <dir> -name '*.php' -not -path '*/vendor/*' | wc -l
# php_loc:   find <dir> -name '*.php' -not -path '*/vendor/*' -exec cat {} + | wc -l
applications:
  laravel-skeleton:
    repo: https://github.com/laravel/laravel.git
    pin: <sha-from-step-2>
    laravel: "<constraint at that sha>"
    php: "<php constraint at that sha>"
    licence: MIT
    php_files: <count>
    php_loc: <count>
    wave: 1
    pr_subset: true
    rationale: >
      The clean-run control from the parent plan. Small enough to run on every PR, and a
      framework skeleton should produce few or no findings, so a sudden crop of them is a
      strong signal that a rule has become indiscriminate.
```

- [ ] **Step 4: Gitignore the scan artifacts**

Append to `.gitignore`:

```
# Corpus scan output. Regenerated by scripts/corpus.py scan; never committed.
# The triage files are the approved record, so committing reports would create a second
# answer to what a scan found.
corpus/reports/
```

- [ ] **Step 5: Create the triage directory**

```bash
mkdir -p corpus/triage && touch corpus/triage/.gitkeep
```

- [ ] **Step 6: Verify a fresh clone gets the pin**

Run: `git submodule status`
Expected: one line for `corpus/laravel-skeleton` at the chosen SHA, with no `+` prefix. A `+`
means the checked-out commit differs from the recorded pointer.

- [ ] **Step 7: Commit**

```bash
git add .gitmodules corpus/ .gitignore
git commit -m "feat: enrol the laravel skeleton as the first corpus submodule"
```

---

### Task 9c: `scripts/corpus.py scan`

**Files:**
- Create: `scripts/corpus.py`
- Modify: `pyproject.toml` (mypy `files`, ruff `per-file-ignores`)

**Interfaces:**
- Consumes: `corpus/pins.yml` from Task 9b.
- Produces: `load_pins(path: Path) -> dict[str, Pin]`, `Pin` (frozen dataclass with fields
  `name: str`, `repo: str`, `pin: str`, `wave: int`, `pr_subset: bool`),
  `scan_app(name: str, root: Path, out: Path, timeout_s: int) -> Path`. Tasks 9d and 9e import
  these.

- [ ] **Step 1: Register the script with the linters first**

In `pyproject.toml`, change:

```toml
[tool.mypy]
strict = true
files = ["src"]
```

to:

```toml
[tool.mypy]
strict = true
# scripts/corpus.py computes the NFR-6 precision number that gates the release. A silent
# type error there is a wrong number in a report people trust, so it is checked like src/.
files = ["src", "scripts/corpus.py"]
```

and add to `[tool.ruff.lint.per-file-ignores]`:

```toml
"scripts/corpus.py" = ["T20"]
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_corpus_precision.py`:

```python
"""The corpus harness, and the harness's own failure modes.

A precision harness that is itself buggy fails in the most dangerous direction, because the
common bug is dropping findings on a join miss, which reports a BETTER number than reality.
So every way this is supposed to refuse gets its own case, exactly as tests/test_corpus.py
does for the fixture harness.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from corpus import Pin, load_pins  # noqa: E402


def test_load_pins_reads_name_repo_and_sha(tmp_path: Path) -> None:
    path = tmp_path / "pins.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "applications": {
                    "laravel-skeleton": {
                        "repo": "https://example.invalid/laravel.git",
                        "pin": "abc123",
                        "wave": 1,
                        "pr_subset": True,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    pins = load_pins(path)
    assert pins["laravel-skeleton"] == Pin(
        name="laravel-skeleton",
        repo="https://example.invalid/laravel.git",
        pin="abc123",
        wave=1,
        pr_subset=True,
    )


def test_load_pins_rejects_a_missing_sha(tmp_path: Path) -> None:
    """An unpinned application is not reproducible, so it is a hard error, not a default."""
    path = tmp_path / "pins.yml"
    path.write_text(
        yaml.safe_dump(
            {"applications": {"koel": {"repo": "https://example.invalid/koel.git"}}}
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="koel"):
        load_pins(path)


def test_load_pins_on_an_empty_document_returns_no_applications(tmp_path: Path) -> None:
    """An empty corpus must read as empty, not crash: wave 1 starts with one application."""
    path = tmp_path / "pins.yml"
    path.write_text("applications: {}\n", encoding="utf-8")
    assert load_pins(path) == {}


def test_a_collapsed_parse_rate_is_refused() -> None:
    """Invariant 4. Unparsed files produce no findings, so they inflate precision twice
    over: no true positives lost that anyone notices, and no false positives either."""
    from corpus import check_coverage

    with pytest.raises(RuntimeError, match="below the"):
        check_coverage("monica", {"coverage": {"parse_success_rate": 0.62}})


def test_a_healthy_parse_rate_is_accepted() -> None:
    """The floor must be a real threshold, not a constant that rejects everything."""
    from corpus import check_coverage

    check_coverage("monica", {"coverage": {"parse_success_rate": 0.999}})
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_corpus_precision.py -v`
Expected: FAIL, `ModuleNotFoundError: No module named 'corpus'`

- [ ] **Step 4: Write the implementation**

Create `scripts/corpus.py`:

```python
"""The corpus precision harness.

Dev tooling, not shipped: it is run from the repository, never imported by src/. It is
nonetheless type-checked and linted like src/, because it computes the NFR-6 precision
number that gates the v0.1 release.

Usage:
    uv run python scripts/corpus.py scan [app]
    uv run python scripts/corpus.py triage <app>
    uv run python scripts/corpus.py report
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "corpus"
PINS = CORPUS / "pins.yml"
REPORTS = CORPUS / "reports"

# Generous, because the engine is known to be far over its NFR-1 budget on real
# applications (see the design's "Measured facts"). The point of the timeout is to turn a
# hang into a loud failure, not to enforce the performance target.
DEFAULT_TIMEOUT_S = 3600

# docs/22-testing sets the corpus parse floor at 99.5%. Below it, a report's findings cover
# only a fraction of the code, so both its precision and its silence are meaningless.
MIN_PARSE_RATE = 0.995


@dataclass(frozen=True)
class Pin:
    """One enrolled application, pinned to an exact commit."""

    name: str
    repo: str
    pin: str
    wave: int = 1
    pr_subset: bool = False


def load_pins(path: Path = PINS) -> dict[str, Pin]:
    """Read `corpus/pins.yml`.

    An application without a `pin` raises rather than defaulting to HEAD. A corpus that
    silently tracks a moving target produces precision numbers that cannot be compared
    between runs, which defeats the entire measurement.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    applications = document.get("applications") or {}
    pins: dict[str, Pin] = {}
    for name, entry in sorted(applications.items()):
        sha = entry.get("pin")
        if not sha:
            raise ValueError(f"application {name} has no pin; an unpinned corpus is not reproducible")
        pins[name] = Pin(
            name=name,
            repo=entry.get("repo", ""),
            pin=str(sha),
            wave=int(entry.get("wave", 1)),
            pr_subset=bool(entry.get("pr_subset", False)),
        )
    return pins


def scan_app(name: str, root: Path, out: Path, timeout_s: int = DEFAULT_TIMEOUT_S) -> Path:
    """Scan one application, writing its JSON report.

    A crash, a timeout or a non-zero exit is raised, never swallowed. An empty report would
    be counted as zero findings and zero false positives, which scores 100% precision: the
    most dangerous possible way for this harness to fail.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            ["uv", "run", "vigilloo", "scan", str(root), "--format", "json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{name}: scan exceeded {timeout_s}s; refusing to record a partial report") from exc

    if completed.returncode != 0:
        raise RuntimeError(f"{name}: scan exited {completed.returncode}: {completed.stderr[-500:]}")

    # Parse before writing. A truncated document must fail here rather than become a report
    # that reads as "no findings".
    document = json.loads(completed.stdout)
    if "findings" not in document or "coverage" not in document:
        raise RuntimeError(f"{name}: report is missing required keys; refusing to record it")

    check_coverage(name, document)

    out.write_text(completed.stdout, encoding="utf-8")
    return out


def check_coverage(name: str, document: dict[str, object]) -> None:
    """Refuse a report whose parse rate is below floor.

    Invariant 4: coverage is reported, never hidden. A clean result over a codebase that
    largely failed to parse is a lie, and here it would also inflate precision, because
    unparsed files produce no findings and therefore no false positives either.

    Separate from `scan_app` so it is testable without running a scan.
    """
    coverage = document["coverage"]
    assert isinstance(coverage, dict)
    parse_rate = float(coverage["parse_success_rate"])
    if parse_rate < MIN_PARSE_RATE:
        raise RuntimeError(
            f"{name}: parse success rate {parse_rate:.1%} is below the {MIN_PARSE_RATE:.1%} floor; "
            "refusing to record a report whose findings cover a fraction of the code"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Corpus precision harness.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan enrolled applications.")
    scan.add_argument("app", nargs="?", help="Application name; omit to scan all.")

    args = parser.parse_args(argv)
    pins = load_pins()

    if args.command == "scan":
        selected = [pins[args.app]] if args.app else list(pins.values())
        for pin in selected:
            report = scan_app(pin.name, CORPUS / pin.name, REPORTS / f"{pin.name}.json")
            print(f"{pin.name}: wrote {report.relative_to(REPO_ROOT)}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/test_corpus_precision.py -v`
Expected: 5 passed

- [ ] **Step 6: Run the scan end to end**

Run: `uv run python scripts/corpus.py scan laravel-skeleton`
Expected: writes `corpus/reports/laravel-skeleton.json` and prints the path.

- [ ] **Step 7: Run the four gates and commit**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
git add scripts/corpus.py tests/test_corpus_precision.py pyproject.toml
git commit -m "feat: add the corpus scan command, type-checked like src"
```

---

### Task 9d: The triage record

**Files:**
- Modify: `scripts/corpus.py`
- Modify: `tests/test_corpus_precision.py`

**Interfaces:**
- Consumes: `Pin`, `load_pins` from Task 9c.
- Produces: `Verdict` (a `str` alias; the permitted values live in the `VERDICTS` tuple and are
  enforced at load time, so a hand-edited typo raises instead of silently counting as
  unreviewed), `TriageEntry` (frozen
  dataclass: `verdict: Verdict`, `rule: str`, `note: str`, `seen_at: str`),
  `load_triage(path: Path) -> dict[str, TriageEntry]`,
  `save_triage(path, pin: str, ruleset: str, entries: dict[str, TriageEntry]) -> None`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_corpus_precision.py`:

```python
def test_triage_round_trips_and_sorts_by_fingerprint(tmp_path: Path) -> None:
    """Invariant 8: the file must be byte-identical given the same entries in any order."""
    from corpus import TriageEntry, load_triage, save_triage

    path = tmp_path / "monica.yml"
    entries = {
        "ffff000000000001": TriageEntry("false", "laravel.no-throttle", "Public API.", "routes/api.php:9"),
        "0000000000000002": TriageEntry("true", "php.sql-injection", "Unbound.", "app/X.php:44"),
    }
    save_triage(path, pin="abc123", ruleset="b35162f4d187c91c", entries=entries)
    first = path.read_text(encoding="utf-8")

    save_triage(path, pin="abc123", ruleset="b35162f4d187c91c", entries=dict(reversed(list(entries.items()))))
    assert path.read_text(encoding="utf-8") == first
    assert first.index("0000000000000002") < first.index("ffff000000000001")

    assert load_triage(path) == entries


def test_load_triage_rejects_an_unknown_verdict(tmp_path: Path) -> None:
    """A typo in a hand-edited verdict must not silently drop out of the precision count."""
    from corpus import load_triage

    path = tmp_path / "monica.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "pin": "abc123",
                "reviewed_ruleset": "b35162f4d187c91c",
                "findings": {"aaaa000000000001": {"verdict": "yes", "rule": "php.sql-injection"}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="yes"):
        load_triage(path)


def test_load_triage_on_a_missing_file_is_empty(tmp_path: Path) -> None:
    """A newly enrolled application has no verdicts yet; that is not an error."""
    from corpus import load_triage

    assert load_triage(tmp_path / "absent.yml") == {}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_corpus_precision.py -v`
Expected: FAIL, `ImportError: cannot import name 'TriageEntry'`

- [ ] **Step 3: Write the implementation**

Add to `scripts/corpus.py`, above `main`:

```python
VERDICTS = ("true", "false", "unreviewed")
Verdict = str


@dataclass(frozen=True)
class TriageEntry:
    """One human verdict on one finding.

    `seen_at` is written by the harness and never read back. It exists so a reviewer opening
    the file months later is not reading bare hex. Reading it would create a second answer
    to where a finding is, and the two would disagree after the first pin bump.
    """

    verdict: Verdict
    rule: str
    note: str = ""
    seen_at: str = ""


def load_triage(path: Path) -> dict[str, TriageEntry]:
    """Read one application's verdicts, keyed by fingerprint."""
    if not path.exists():
        return {}
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries: dict[str, TriageEntry] = {}
    for fingerprint, entry in (document.get("findings") or {}).items():
        verdict = entry.get("verdict", "unreviewed")
        if verdict not in VERDICTS:
            raise ValueError(f"{path.name}: {fingerprint} has unknown verdict {verdict!r}, expected one of {VERDICTS}")
        entries[str(fingerprint)] = TriageEntry(
            verdict=verdict,
            rule=str(entry.get("rule", "")),
            note=str(entry.get("note", "")),
            seen_at=str(entry.get("seen_at", "")),
        )
    return entries


def save_triage(path: Path, pin: str, ruleset: str, entries: dict[str, TriageEntry]) -> None:
    """Write verdicts, sorted by fingerprint.

    `sort_keys=True` plus the sorted dict keeps the file byte-identical for the same
    content, so a diff shows what a human changed rather than what a dict reordered.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "pin": pin,
        "reviewed_ruleset": ruleset,
        "findings": {
            fingerprint: {
                "verdict": entry.verdict,
                "rule": entry.rule,
                "note": entry.note,
                "seen_at": entry.seen_at,
            }
            for fingerprint, entry in sorted(entries.items())
        },
    }
    path.write_text(yaml.safe_dump(document, sort_keys=True, default_flow_style=False), encoding="utf-8")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_corpus_precision.py -v`
Expected: 8 passed

- [ ] **Step 5: Run the four gates and commit**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
git add scripts/corpus.py tests/test_corpus_precision.py
git commit -m "feat: add the fingerprint-keyed triage record"
```

---

### Task 9e: Precision, the per-rule quota, and the report

**Files:**
- Modify: `scripts/corpus.py`
- Modify: `tests/test_corpus_precision.py`

**Interfaces:**
- Consumes: `TriageEntry`, `load_triage` from Task 9d; `diff_fingerprints` from Task 9a.
- Produces: `RulePrecision` (frozen dataclass: `rule: str`, `true_count: int`,
  `false_count: int`, `unreviewed_count: int`, `precision: float | None`),
  `select_for_review(findings: list[dict[str, object]], quota: int) -> list[str]`,
  `compute_precision(findings, triage) -> list[RulePrecision]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_corpus_precision.py`:

```python
def _finding(fingerprint: str, rule: str) -> dict[str, object]:
    return {"fingerprint": fingerprint, "rule_id": rule}


def test_precision_is_none_when_nothing_is_reviewed() -> None:
    """Undefined, not 0% and not 100%. Both would be wrong in opposite directions."""
    from corpus import compute_precision

    rows = compute_precision([_finding("aaa", "php.sql-injection")], {})
    assert rows[0].precision is None
    assert rows[0].unreviewed_count == 1


def test_precision_counts_only_reviewed_verdicts() -> None:
    from corpus import TriageEntry, compute_precision

    findings = [_finding("a", "r"), _finding("b", "r"), _finding("c", "r"), _finding("d", "r")]
    triage = {
        "a": TriageEntry("true", "r"),
        "b": TriageEntry("true", "r"),
        "c": TriageEntry("false", "r"),
    }
    row = compute_precision(findings, triage)[0]
    assert (row.true_count, row.false_count, row.unreviewed_count) == (2, 1, 1)
    assert row.precision == pytest.approx(2 / 3)


def test_quota_is_per_rule_so_a_noisy_rule_cannot_crowd_others_out() -> None:
    """The failure a flat cap produces: one rule eats the budget, 31 rules go unmeasured.

    laravel.raw-query alone is 28 of 65 findings on tests/fixtures/laravel-minimal, so this
    is the real distribution, not a hypothetical one.
    """
    from corpus import select_for_review

    findings = [_finding(f"n{i:03d}", "laravel.raw-query") for i in range(50)]
    findings.append(_finding("z999", "php.sql-injection"))
    selected = select_for_review(findings, quota=2)
    assert "z999" in selected
    assert len([f for f in selected if f.startswith("n")]) == 2


def test_quota_selection_is_stable_across_runs() -> None:
    """Churn in the reviewed set would silently invalidate prior verdicts."""
    from corpus import select_for_review

    findings = [_finding("ccc", "r"), _finding("aaa", "r"), _finding("bbb", "r")]
    assert select_for_review(findings, quota=2) == select_for_review(list(reversed(findings)), quota=2)
    assert select_for_review(findings, quota=2) == ["aaa", "bbb"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_corpus_precision.py -v`
Expected: FAIL, `ImportError: cannot import name 'compute_precision'`

- [ ] **Step 3: Write the implementation**

Add to `scripts/corpus.py`:

`from collections import defaultdict` goes with the other imports at the top of the file, not
inline where it appears below.

```python
from collections import defaultdict

DEFAULT_QUOTA = 20


@dataclass(frozen=True)
class RulePrecision:
    """One row of the precision table.

    `precision` is None when nothing has been reviewed. That is undefined, not zero: a gate
    treating it as 0% fails the build on a corpus nobody has read, and one treating it as
    100% passes vacuously.
    """

    rule: str
    true_count: int
    false_count: int
    unreviewed_count: int
    precision: float | None


def select_for_review(findings: list[dict[str, object]], quota: int = DEFAULT_QUOTA) -> list[str]:
    """Choose up to `quota` fingerprints per rule, in fingerprint order.

    Per-rule rather than a flat cap: a flat cap is consumed by whichever rule is noisiest,
    leaving most rules with no precision estimate at all, and the noisy rules are exactly
    what Task 10 needs to find.

    Fingerprint order rather than report order: selection must be identical across runs, or
    the reviewed set churns and prior verdicts stop applying.
    """
    by_rule: dict[str, list[str]] = defaultdict(list)
    for finding in findings:
        by_rule[str(finding["rule_id"])].append(str(finding["fingerprint"]))
    selected: list[str] = []
    for rule in sorted(by_rule):
        selected.extend(sorted(set(by_rule[rule]))[:quota])
    return sorted(selected)


def compute_precision(
    findings: list[dict[str, object]], triage: dict[str, TriageEntry]
) -> list[RulePrecision]:
    """Count verdicts per rule and derive precision over the reviewed ones."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"true": 0, "false": 0, "unreviewed": 0})
    for finding in findings:
        rule = str(finding["rule_id"])
        entry = triage.get(str(finding["fingerprint"]))
        verdict = entry.verdict if entry else "unreviewed"
        counts[rule][verdict] += 1

    rows: list[RulePrecision] = []
    for rule in sorted(counts):
        c = counts[rule]
        reviewed = c["true"] + c["false"]
        rows.append(
            RulePrecision(
                rule=rule,
                true_count=c["true"],
                false_count=c["false"],
                unreviewed_count=c["unreviewed"],
                precision=(c["true"] / reviewed) if reviewed else None,
            )
        )
    return rows
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_corpus_precision.py -v`
Expected: 12 passed

- [ ] **Step 5: Wire the `report` subcommand**

In `main`, add the parser and branch:

```python
    sub.add_parser("report", help="Print the precision table and drift.")
```

```python
    if args.command == "report":
        for pin in pins.values():
            report_path = REPORTS / f"{pin.name}.json"
            if not report_path.exists():
                raise SystemExit(f"{pin.name}: no report; run `scan` first")
            document = json.loads(report_path.read_text(encoding="utf-8"))
            findings = document["findings"]
            triage = load_triage(CORPUS / "triage" / f"{pin.name}.yml")

            print(f"\n{pin.name} @ {pin.pin[:12]}  ({len(findings)} findings)")
            print(f"{'rule':<40} {'true':>5} {'false':>6} {'unrev':>6} {'precision':>10}")
            for row in compute_precision(findings, triage):
                shown = "undefined" if row.precision is None else f"{row.precision:.1%}"
                print(f"{row.rule:<40} {row.true_count:>5} {row.false_count:>6} {row.unreviewed_count:>6} {shown:>10}")

            drift = diff_fingerprints(
                current=[str(f["fingerprint"]) for f in findings], approved=list(triage)
            )
            print(f"drift: {len(drift.added)} new, {len(drift.removed)} gone")
        return 0
```

Add this import to the top of the file, alongside the other imports. No `sys.path` juggling is
needed: `src` is installed as the `vigilloo` package in the dev environment, so the absolute
name resolves. This script is outside `src/`, so it uses the absolute import, not a relative
one.

```python
from vigilloo.baseline import diff_fingerprints
```

- [ ] **Step 6: Run it end to end**

```bash
uv run python scripts/corpus.py scan laravel-skeleton
uv run python scripts/corpus.py report
```

Expected: a table with every firing rule, `undefined` precision throughout (nothing is
triaged yet), and a drift line reporting every finding as new.

- [ ] **Step 7: Run the four gates and commit**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
git add scripts/corpus.py tests/test_corpus_precision.py
git commit -m "feat: add per-rule precision, the review quota and the corpus report"
```

---

### Task 9f: The `triage` subcommand

**Files:**
- Modify: `scripts/corpus.py`

**Interfaces:**
- Consumes: everything from Tasks 9c to 9e.
- Produces: no new public names. Writes `corpus/triage/<app>.yml`.

- [ ] **Step 1: Add the subcommand**

In `main`:

```python
    triage_parser = sub.add_parser("triage", help="Record verdicts for one application.")
    triage_parser.add_argument("app")
    triage_parser.add_argument("--quota", type=int, default=DEFAULT_QUOTA)
```

```python
    if args.command == "triage":
        pin = pins[args.app]
        report_path = REPORTS / f"{pin.name}.json"
        if not report_path.exists():
            raise SystemExit(f"{pin.name}: no report; run `scan` first")
        document = json.loads(report_path.read_text(encoding="utf-8"))
        ruleset = str(document["tool"]["ruleset_hash"])
        findings = {str(f["fingerprint"]): f for f in document["findings"]}

        triage_path = CORPUS / "triage" / f"{pin.name}.yml"
        entries = load_triage(triage_path)

        # Seed every selected finding as `unreviewed`, preserving any verdict already
        # recorded. Nothing here overwrites a human decision.
        for fingerprint in select_for_review(document["findings"], quota=args.quota):
            if fingerprint in entries:
                continue
            finding = findings[fingerprint]
            location = finding["location"]
            entries[fingerprint] = TriageEntry(
                verdict="unreviewed",
                rule=str(finding["rule_id"]),
                note="",
                seen_at=f"{location['file']}:{location['start_line']}",
            )

        save_triage(triage_path, pin=pin.pin, ruleset=ruleset, entries=entries)
        pending = sum(1 for e in entries.values() if e.verdict == "unreviewed")
        print(f"{pin.name}: {len(entries)} selected, {pending} awaiting a verdict")
        print(f"Edit {triage_path.relative_to(REPO_ROOT)} and set each verdict to true or false.")
        return 0
```

- [ ] **Step 2: Run it end to end**

```bash
uv run python scripts/corpus.py triage laravel-skeleton
```

Expected: writes `corpus/triage/laravel-skeleton.yml` with every selected finding at
`verdict: unreviewed`, and prints the count awaiting review.

- [ ] **Step 3: Verify verdicts survive re-running**

Hand-edit one entry in `corpus/triage/laravel-skeleton.yml` to `verdict: false`, then run
`uv run python scripts/corpus.py triage laravel-skeleton` again.
Expected: the edited verdict is unchanged. Re-seeding must never overwrite a human decision.

- [ ] **Step 4: Run the four gates and commit**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
git add scripts/corpus.py corpus/triage/laravel-skeleton.yml
git commit -m "feat: add the triage command, seeding verdicts without overwriting them"
```

---

### Task 9g: CI wiring

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/corpus-nightly.yml`

**Interfaces:**
- Consumes: `scripts/corpus.py` from Tasks 9c to 9f.

- [ ] **Step 1: Add the PR-time subset job**

Append to `.github/workflows/ci.yml`, following the existing named-step pattern so a failure
reads as "corpus subset" rather than as one red test among hundreds:

```yaml
  corpus-subset:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - uses: astral-sh/setup-uv@v5
      - run: uv sync --all-extras
      - name: Corpus subset (PR-time)
        run: |
          uv run python scripts/corpus.py scan laravel-skeleton
          uv run python scripts/corpus.py report
```

Only the skeleton runs here. The engine is far over its NFR-1 budget on real applications, and
PR latency sits on the critical path of a protected branch.

- [ ] **Step 2: Add the nightly workflow**

Create `.github/workflows/corpus-nightly.yml`:

```yaml
name: Corpus nightly

on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:

jobs:
  corpus:
    runs-on: ubuntu-latest
    timeout-minutes: 180
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - uses: astral-sh/setup-uv@v5
      - run: uv sync --all-extras
      - name: Full corpus precision and drift
        run: |
          uv run python scripts/corpus.py scan
          uv run python scripts/corpus.py report
```

`timeout-minutes: 180` is deliberate and generous: the design records the engine at more than
22x its NFR-1 budget on a mid-size application. A job that is killed with no output looks
identical to one that found nothing.

- [ ] **Step 3: Verify the workflow parses**

Run: `uv run python -c "import yaml,pathlib; yaml.safe_load(pathlib.Path('.github/workflows/corpus-nightly.yml').read_text())"`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/corpus-nightly.yml
git commit -m "ci: run the corpus subset on PRs and the full corpus nightly"
```

---

### Task 9h: Correct the specs

Docs are the spec, and this task lands the corrections the design identified.

**Files:**
- Modify: `docs/22-testing/README.md`
- Modify: `docs/24-roadmap/README.md`
- Modify: `docs/plans/2026-08-20-task-9-corpus-design.md`

- [ ] **Step 1: Resolve the cadence contradiction**

`docs/22-testing/README.md` line 13 says the Corpus layer runs "every PR"; line 185 says "Full
corpus runs nightly; PRs run unit + fixture + regression only". Change the Layers table row to
match the Tooling section:

```
| **Corpus** | Real open-source Laravel applications | minutes | nightly, subset on PRs |
```

- [ ] **Step 2: Update the real-applications framing**

In the "Real applications" paragraph, replace the snapshot-only description with the single
record serving both gates. The current text says expectations are "a reviewed snapshot rather
than ground truth, so the test asserts 'no new findings and no lost findings versus the
approved snapshot'". Add that the same `corpus/triage/<app>.yml`, keyed by fingerprint, also
carries a three-state verdict per finding, from which precision is counted over reviewed
verdicts only, and that unreviewed findings are reported separately and never folded into
precision.

- [ ] **Step 3: Add the roadmap row**

Per the standing rule that per-capability status has one home, add a row to the v0.1 table in
`docs/24-roadmap/README.md` recording the corpus harness, what is built (scan, triage, report,
per-rule precision, drift) and what is not (the gate, which is Task 11, and the applications
beyond wave 1).

- [ ] **Step 4: Flip the design's status**

Change the `**Status:**` line of `docs/plans/2026-08-20-task-9-corpus-design.md` from
`designing.` to `implemented.` The repo convention is that plans are not rewritten as they
ship; the Status line carries current state.

- [ ] **Step 5: Verify no em dashes crept in**

The pattern is built with `printf` rather than typed literally, so this plan does not itself
contain the character it is checking for:

```bash
grep -rn "$(printf '\u2014')" docs/22-testing/README.md docs/24-roadmap/README.md \
  docs/plans/2026-08-20-task-9-corpus-design.md
```

Expected: no matches, exit 1.

- [ ] **Step 6: Run the four gates and commit**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
git add docs/
git commit -m "docs: resolve the corpus cadence contradiction and record the harness"
```

---

## Deferred, with reasons

These are named so they are not discovered mid-execution:

- **The profiling pass.** The design records the engine at more than 22x its NFR-1 budget on
  Monica. A nightly ten-application corpus is not reachable until that is addressed. It wants a
  profile and a systematic-debugging pass, and it is not designed here.
- **Enrolling applications beyond the skeleton.** Each needs its Laravel 9-11 pin found by the
  procedure in Task 9b step 2, its metadata recorded, and its findings triaged. That is
  per-application work gated on the profiling result.
- **CVE pins for recall.** Research: select advisories whose weakness maps to a rule that
  already exists, then assert the pair, found at the vulnerable pin and silent at the fixed
  pin. A CVE for an undetected class would sit permanently unfound and teach nothing.
- **Turning the gate on.** Task 11. This plan wires reporting completely and leaves the
  threshold comparison out, so Task 11 is a small change rather than a rewrite.
