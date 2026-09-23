"""Implementation of the `vigilloo graph` commands.

Surfaces knowledge graph capabilities: graph export (JSON and GraphML),
route attack-surface inventory, and structural statistics.
"""

import json
import sqlite3
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..models import EdgeRow, NodeRow, Route, WalkStats
from ..workspace import Workspace
from . import store
from .core import graph_rows, load_project
from .export import export_graphml, export_json

_AUTH_MIDDLEWARES = frozenset({"auth", "auth:api", "auth:sanctum", "verified"})


def _is_authenticated_route(route: Route) -> bool:
    for m in route.middleware:
        if m in _AUTH_MIDDLEWARES or m.startswith("auth:"):
            return True
    return False


def _get_or_build_graph(
    path: Path,
) -> tuple[Workspace, list[NodeRow], list[EdgeRow], WalkStats, int]:
    workspace = Workspace.open(path)
    stats = WalkStats()

    # Attempt to load from store first
    db_path = workspace.dir / "vigilloo.db"
    if db_path.is_file():
        try:
            conn = sqlite3.connect(db_path)
            try:
                pid = store.project_id_for(conn, workspace.root)
                if pid is not None:
                    nodes, edges = store.graph_for_project(conn, pid)
                    if nodes or edges:
                        file_count = len({n.file_id for n in nodes if n.file_id is not None})
                        return workspace, nodes, edges, stats, file_count
            finally:
                conn.close()
        except Exception:
            pass

    # Build fresh graph in memory
    project = load_project(workspace.root, stats)
    file_ids = {f: i + 1 for i, f in enumerate(sorted(project.files))}
    rows = graph_rows(project, 1, file_ids)
    file_count = len(project.files) + len(project.blade)
    return workspace, list(rows.nodes), list(rows.edges), stats, file_count


def run_graph_export(
    path: Path,
    output_format: str = "json",
    output_file: Path | None = None,
    console: Console | None = None,
) -> int:
    """Export knowledge graph to JSON or GraphML format."""
    if console is None:
        console = Console(stderr=True)

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    fmt = output_format.lower()
    if fmt not in ("json", "graphml"):
        console.print(f"[red]Error: invalid format '{output_format}'. Use json or graphml.[/red]")
        return 2

    _, nodes, edges, _, _ = _get_or_build_graph(resolved_path)

    if fmt == "graphml":
        body = export_graphml(nodes, edges)
    else:
        body = export_json(nodes, edges)

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(body, encoding="utf-8")
        console.print(
            f"[bold green]✓ Exported graph ({len(nodes)} nodes, {len(edges)} edges) "
            f"to {output_file}[/bold green]"
        )
    else:
        sys.stdout.write(body)

    return 0


def run_graph_routes(
    path: Path,
    as_json: bool = False,
    console: Console | None = None,
) -> int:
    """Display the HTTP route attack-surface inventory."""
    if console is None:
        console = Console()

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    workspace = Workspace.open(resolved_path)
    stats = WalkStats()
    project = load_project(workspace.root, stats)

    if as_json:
        routes_data = [
            {
                "uri": r.uri,
                "verbs": list(r.verbs),
                "action": r.action_fqn,
                "middleware": list(r.middleware),
                "auth_required": _is_authenticated_route(r),
                "file": str(r.span.file),
                "line": r.span.start_line,
            }
            for r in sorted(project.routes, key=lambda r: (r.uri, r.verbs))
        ]
        sys.stdout.write(json.dumps(routes_data, indent=2) + "\n")
        return 0

    if not project.routes:
        console.print(f"[yellow]No HTTP routes discovered in {path}.[/yellow]")
        return 0

    table = Table(title=f"Route Inventory for {resolved_path.name}")
    table.add_column("Verbs", style="cyan")
    table.add_column("URI", style="bold")
    table.add_column("Action", style="green")
    table.add_column("Middleware")
    table.add_column("Auth", justify="center")

    auth_count = 0
    public_count = 0

    sorted_routes = sorted(project.routes, key=lambda r: (r.uri, r.verbs))
    for r in sorted_routes:
        is_auth = _is_authenticated_route(r)
        if is_auth:
            auth_count += 1
            auth_badge = "[green]Authenticated[/green]"
        else:
            public_count += 1
            auth_badge = "[yellow]Public[/yellow]"

        verbs_str = ", ".join(r.verbs)
        mw_str = ", ".join(r.middleware) if r.middleware else "(none)"
        table.add_row(verbs_str, r.uri, r.action_fqn, mw_str, auth_badge)

    console.print()
    console.print(table)
    console.print(
        f"\nTotal Routes: [bold]{len(project.routes)}[/bold] "
        f"([green]{auth_count} Authenticated[/green], [yellow]{public_count} Public[/yellow])\n"
    )
    return 0


def run_graph_stats(
    path: Path,
    as_json: bool = False,
    console: Console | None = None,
) -> int:
    """Display knowledge graph composition and resolution statistics."""
    if console is None:
        console = Console()

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    workspace, nodes, edges, stats, file_count = _get_or_build_graph(resolved_path)

    node_kinds = Counter(n.kind for n in nodes)
    edge_kinds = Counter(e.kind for e in edges)

    if as_json:
        node_counts = dict(sorted(node_kinds.items()))
        edge_counts = dict(sorted(edge_kinds.items()))
        stats_data = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_files": file_count,
            "nodes_by_kind": node_counts,
            "edges_by_kind": edge_counts,
        }
        sys.stdout.write(json.dumps(stats_data, indent=2) + "\n")
        return 0

    table = Table(title=f"Knowledge Graph Statistics for {resolved_path.name}")
    table.add_column("Entity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Breakdown / Details")

    table.add_row("Total Files", str(file_count), "Analyzed source files")

    node_breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(node_kinds.items()))
    table.add_row("Total Nodes", str(len(nodes)), node_breakdown or "None")

    edge_breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(edge_kinds.items()))
    table.add_row("Total Edges", str(len(edges)), edge_breakdown or "None")

    total_calls = stats.resolved + stats.unresolved
    if total_calls > 0:
        pct = (stats.resolved / total_calls) * 100.0
        table.add_row(
            "Call Resolution",
            f"{pct:.1f}%",
            f"{stats.resolved}/{total_calls} calls resolved",
        )

    console.print()
    console.print(table)
    console.print()
    return 0


def run_graph_build(
    path: Path,
    console: Console | None = None,
) -> int:
    """Build and update the knowledge graph in the workspace store."""
    if console is None:
        console = Console()

    resolved_path = path.resolve()
    if not resolved_path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not resolved_path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    workspace = Workspace.open(resolved_path)
    stats = WalkStats()
    project = load_project(workspace.root, stats)

    try:
        conn = store.connect(workspace)
        try:
            now = datetime.now(UTC)
            pid = store._upsert_project(conn, workspace.root, now)
            file_ids = store._upsert_files(conn, pid, project, now.isoformat())
            rows = graph_rows(project, pid, file_ids)
            store._replace_graph(conn, pid, rows)
        finally:
            conn.close()
    except Exception as exc:
        console.print(f"[yellow]Warning: could not write to store: {exc}[/yellow]")
        file_ids = {f: i + 1 for i, f in enumerate(sorted(project.files))}
        rows = graph_rows(project, 1, file_ids)

    console.print(
        f"[bold green]✓ Successfully built knowledge graph for '{resolved_path.name}': "
        f"{len(rows.nodes)} nodes, {len(rows.edges)} edges across "
        f"{len(project.files) + len(project.blade)} files.[/bold green]"
    )
    return 0
