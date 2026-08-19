"""Report rendering, one module per format.

Every format renders the same `ReportDocument`, built once from a scan's
findings and coverage. Two formats that each walked the `Finding` list
themselves would eventually disagree about what a scan found, and the one a
developer reads is not the one CI gates on.
"""

from .document import ReportDocument, ReportMetadata, build_document
from .json_report import render_json
from .terminal import render, render_coverage

__all__ = [
    "ReportDocument",
    "ReportMetadata",
    "build_document",
    "render",
    "render_coverage",
    "render_json",
]
