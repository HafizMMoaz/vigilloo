"""The fingerprint set diff that drift detection and `vigilloo baseline` both read.

Backward-compatibility shim re-exporting vigilloo.cli.baseline.
"""

from .cli.baseline import (
    DEFAULT_BASELINE_REL_PATH,
    diff_fingerprints,
    load_baseline_fingerprints,
    save_baseline_file,
)

__all__ = [
    "DEFAULT_BASELINE_REL_PATH",
    "diff_fingerprints",
    "load_baseline_fingerprints",
    "save_baseline_file",
]
