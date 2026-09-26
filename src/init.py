"""Implementation of the `vigilloo init` command.

Backward-compatibility shim re-exporting vigilloo.cli.init.
"""

from .cli.init import run_init

__all__ = ["run_init"]
