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
