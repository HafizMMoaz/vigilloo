"""Command line interface for Vigilloo.

Backward-compatibility shim re-exporting vigilloo.cli.
"""

from .cli import app, main

__all__ = ["app", "main"]
