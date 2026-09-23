"""The SQLite store: `.vigilloo/vigilloo.db`, the graph tables, and one row per scan
and per finding.

Backward-compatibility shim re-exporting vigilloo.graph.store.
"""

from .graph.store import (  # noqa: F401
    EdgeRow,
    NodeRow,
    StoredFinding,
    connect,
    findings_by_fingerprint,
    findings_for_scan,
    graph_for_project,
    insert_edges,
    insert_nodes,
    latest_scan,
    load_symbols,
    project_id_for,
    record_scan,
    save_symbols,
)

__all__ = [
    "EdgeRow",
    "NodeRow",
    "StoredFinding",
    "connect",
    "findings_by_fingerprint",
    "findings_for_scan",
    "graph_for_project",
    "insert_edges",
    "insert_nodes",
    "latest_scan",
    "load_symbols",
    "project_id_for",
    "record_scan",
    "save_symbols",
]
