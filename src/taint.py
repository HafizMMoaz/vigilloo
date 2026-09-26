"""Taint propagation from route entry points to SQL sinks.

Backward-compatibility shim re-exporting vigilloo.analysis.taint.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from .analysis import taint as _target
from .analysis.taint import (
    LocalState,
    WalkStats,
    expr_kinds,
    find_taint_paths,
)

if TYPE_CHECKING:
    _Base = object
else:
    _Base = sys.modules[__name__].__class__


class _TaintShim(_Base):
    """Shim proxy ensuring dynamic modifications propagate to vigilloo.analysis.taint."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_target, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(_target, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _TaintShim  # type: ignore[assignment]

__all__ = [
    "LocalState",
    "WalkStats",
    "expr_kinds",
    "find_taint_paths",
]
