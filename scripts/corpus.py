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
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

from vigilloo.baseline import diff_fingerprints  # type: ignore[import-not-found]

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
            raise ValueError(
                f"application {name} has no pin; an unpinned corpus is not reproducible"
            )
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
            raise RuntimeError(
                f"{name}: scan exceeded {timeout_s}s; refusing to record a partial report"
            ) from exc

        if completed.returncode != 0:
            raise RuntimeError(
                f"{name}: scan exited {completed.returncode}: {completed.stderr[-500:]}"
            )

        # Parse before writing. A truncated document must fail here rather than become a
        # report that reads as "no findings".
        document = json.loads(completed.stdout)
        if "findings" not in document or "coverage" not in document:
            raise RuntimeError(f"{name}: report is missing required keys; refusing to record it")

        check_coverage(name, document)

        out.write_text(completed.stdout, encoding="utf-8")
        return out
    finally:
        # `vigilloo scan` unconditionally creates `<root>/.vigilloo` (Workspace.open in
        # src/workspace/__init__.py) with no flag to suppress it. `root` here is a corpus
        # application's git submodule checkout, so every scan would otherwise leave that
        # submodule's working tree dirty - a state nobody cleans up by hand in CI. Remove it
        # on every exit path (success, raise, or timeout), using ignore_errors so a cleanup
        # failure can never mask the real scan failure that is propagating past this block.
        shutil.rmtree(root / ".vigilloo", ignore_errors=True)


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
            raise ValueError(
                f"{path.name}: {fingerprint} has unknown verdict {verdict!r}, "
                f"expected one of {VERDICTS}"
            )
        entries[str(fingerprint)] = TriageEntry(
            verdict=verdict,
            rule=str(entry.get("rule", "")),
            note=str(entry.get("note", "")),
            seen_at=str(entry.get("seen_at", "")),
        )
    return entries


def save_triage(path: Path, pin: str, ruleset: str, entries: dict[str, TriageEntry]) -> None:
    """Write verdicts, sorted by fingerprint.

    `sort_keys=True` keeps the file byte-identical for the same
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
            for fingerprint, entry in entries.items()
        },
    }
    path.write_text(
        yaml.safe_dump(document, sort_keys=True, default_flow_style=False), encoding="utf-8"
    )


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
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"true": 0, "false": 0, "unreviewed": 0}
    )
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Corpus precision harness.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan enrolled applications.")
    scan.add_argument("app", nargs="?", help="Application name; omit to scan all.")
    sub.add_parser("report", help="Print the precision table and drift.")

    args = parser.parse_args(argv)
    pins = load_pins()

    if args.command == "scan":
        selected = [pins[args.app]] if args.app else list(pins.values())
        for pin in selected:
            report = scan_app(pin.name, CORPUS / pin.name, REPORTS / f"{pin.name}.json")
            print(f"{pin.name}: wrote {report.relative_to(REPO_ROOT)}")
        return 0

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
                print(
                    f"{row.rule:<40} {row.true_count:>5} {row.false_count:>6} "
                    f"{row.unreviewed_count:>6} {shown:>10}"
                )

            drift = diff_fingerprints(
                current=[str(f["fingerprint"]) for f in findings], approved=list(triage)
            )
            print(f"drift: {len(drift.added)} new, {len(drift.removed)} gone")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
