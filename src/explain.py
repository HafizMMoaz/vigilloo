"""Implementation of the `vigilloo explain` command.

Backward-compatibility shim re-exporting vigilloo.cli.explain.
"""

from .cli.explain import run_explain

__all__ = ["run_explain"]
