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
