"""Report rendering, one module per format.

Every format renders the same `ReportDocument`, built once from a scan's
findings and coverage. Two formats that each walked the `Finding` list
themselves would eventually disagree about what a scan found, and the one a
developer reads is not the one CI gates on.
"""

from .terminal import render, render_coverage

__all__ = ["render", "render_coverage"]
