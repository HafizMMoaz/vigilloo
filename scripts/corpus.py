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
