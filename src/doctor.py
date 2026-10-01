"""Implementation of the `vigilloo doctor` command.

Backward-compatibility shim re-exporting vigilloo.cli.doctor.
"""

from .cli.doctor import run_doctor

__all__ = ["run_doctor"]
