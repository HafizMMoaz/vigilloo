"""Set difference over finding fingerprints and baseline file management.

Drift detection in the corpus harness and `vigilloo baseline` (Task 13) ask the same
question: which findings are new, which are gone, which persist. Answering it in one place
means there is one definition of "the same finding" rather than two that disagree.

Fingerprints rather than ids, deliberately. A fingerprint is location-independent
(invariant 3), so reformatting a file or pulling an upstream commit does not make an
unchanged finding look new.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Finding

DEFAULT_BASELINE_REL_PATH = Path(".vigilloo") / "baseline.json"


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


def load_baseline_fingerprints(path: Path) -> set[str]:
    """Load baseline fingerprints from a JSON baseline file.

    Supports both a JSON list of strings (raw fingerprints) and a JSON list
    of finding dictionaries containing a 'fingerprint' key.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Baseline file does not exist: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file is not valid JSON: {path}") from exc

    if not isinstance(data, list):
        raise ValueError(f"Baseline file must contain a list of items: {path}")

    fingerprints: set[str] = set()
    for item in data:
        if isinstance(item, str):
            fingerprints.add(item)
        elif (
            isinstance(item, dict)
            and "fingerprint" in item
            and isinstance(item["fingerprint"], str)
        ):
            fingerprints.add(item["fingerprint"])
        else:
            raise ValueError(
                f"Baseline file format invalid in {path}: "
                "expected strings or objects with 'fingerprint'"
            )
    return fingerprints


def serialize_findings_for_baseline(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """Format findings for baseline JSON storage, sorted deterministically."""
    records: list[dict[str, Any]] = []
    for f in findings:
        loc = f"{f.span.file}:{f.span.start_line}"
        records.append(
            {
                "fingerprint": f.fingerprint,
                "rule_id": f.rule_id,
                "location": loc,
                "title": f.title,
            }
        )
    # Sort deterministically by fingerprint, rule_id, and location
    records.sort(key=lambda r: (r["fingerprint"], r["rule_id"], r["location"]))
    return records


def save_baseline_file(path: Path, findings: Iterable[Finding]) -> None:
    """Save findings into a formatted baseline JSON file."""
    records = serialize_findings_for_baseline(findings)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(records, indent=2) + "\n"
    path.write_text(content, encoding="utf-8")
