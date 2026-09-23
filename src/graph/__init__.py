"""Knowledge graph package for vigilloo.

Provides the in-memory graph representation (Project), SQLite store,
graph export (JSON, GraphML), node identification, and graph CLI queries.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .core import (
    GraphRows,
    NodeLocator,
    Project,
    coverage,
    error_constructs,
    graph_rows,
    load_project,
)
from .export import JSON_FORMAT_VERSION, export_graphml, export_json
from .ids import node_id
from .queries import (
    run_graph_build,
    run_graph_export,
    run_graph_routes,
    run_graph_stats,
)
from .store import (
    connect,
    findings_by_fingerprint,
    findings_for_scan,
    graph_for_project,
    latest_scan,
    load_symbols,
    project_id_for,
    record_scan,
    save_symbols,
)

if TYPE_CHECKING:
    _Base = object
else:
    _Base = sys.modules[__name__].__class__


class _GraphPackage(_Base):
    """Package proxy ensuring monkeypatched graph attributes propagate to core."""

    def __setattr__(self, name: str, value: object) -> None:
        super().__setattr__(name, value)
        if name == "error_constructs":
            import vigilloo.graph.core as _c

            _c.error_constructs = value  # type: ignore[assignment]


sys.modules[__name__].__class__ = _GraphPackage  # type: ignore[assignment]

__all__ = [
    "GraphRows",
    "JSON_FORMAT_VERSION",
    "NodeLocator",
    "Project",
    "connect",
    "coverage",
    "error_constructs",
    "export_graphml",
    "export_json",
    "findings_by_fingerprint",
    "graph_for_project",
    "graph_rows",
    "latest_scan",
    "load_project",
    "load_symbols",
    "node_id",
    "project_id_for",
    "record_scan",
    "run_graph_build",
    "run_graph_export",
    "run_graph_routes",
    "run_graph_stats",
    "findings_for_scan",
    "save_symbols",
]
