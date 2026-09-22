"""Performance benchmarks guarding NFR scan targets per docs/22-testing.

Guards:
- Scan time, 100k LOC: <= 60s
- Peak memory, 500k LOC: <= 2 GB
"""

import resource
import sys
from pathlib import Path
from typing import Any

import pytest

from vigilloo.graph import load_project
from vigilloo.models import WalkStats
from vigilloo.rules import scan_project
from vigilloo.workspace import Workspace


def get_peak_rss_mb() -> float:
    """Return peak resident set size in megabytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return usage / (1024 * 1024)
    return usage / 1024


def generate_synthetic_app(root_dir: Path, file_count: int, lines_per_file: int = 1000) -> None:
    """Generate a synthetic Laravel project of approximately file_count * lines_per_file LOC."""
    app_dir = root_dir / "app" / "Http" / "Controllers"
    app_dir.mkdir(parents=True, exist_ok=True)
    routes_dir = root_dir / "routes"
    routes_dir.mkdir(parents=True, exist_ok=True)

    routes_lines = ["<?php", "use Illuminate\\Support\\Facades\\Route;"]

    # Calculate methods and statements needed per file to reach target LOC
    methods_per_file = 20
    stmts_per_method = max(1, (lines_per_file - 10) // methods_per_file - 3)

    for i in range(file_count):
        lines = [
            "<?php",
            "namespace App\\Http\\Controllers;",
            "use Illuminate\\Http\\Request;",
            f"class BenchController{i} {{",
        ]
        for m in range(methods_per_file):
            lines.append(f"    public function action{m}(Request $request) {{")
            for s in range(stmts_per_method):
                lines.append(f"        $var_{s} = {s};")
            lines.append("        return $request->input('query');")
            lines.append("    }")
        lines.append("}")
        (app_dir / f"BenchController{i}.php").write_text("\n".join(lines))
        routes_lines.append(
            f"Route::get('/route_{i}', "
            f"[\\App\\Http\\Controllers\\BenchController{i}::class, 'action0']);"
        )

    (routes_dir / "web.php").write_text("\n".join(routes_lines))


@pytest.mark.perf
@pytest.mark.benchmark
def test_scan_time_100k_loc(benchmark: Any, tmp_path: Path) -> None:
    """Assert scan time for 100k LOC completes within 60s per docs/22-testing NFR target."""
    proj_root = tmp_path / "app_100k"
    generate_synthetic_app(proj_root, file_count=100, lines_per_file=1000)

    workspace = Workspace.open(proj_root)

    def run_scan() -> int:
        stats = WalkStats()
        project = load_project(workspace.root, stats)
        findings = scan_project(project, stats)
        return len(findings)

    findings_count = benchmark.pedantic(run_scan, iterations=1, rounds=1)
    assert findings_count == 0

    mean_duration = benchmark.stats["mean"]
    assert mean_duration <= 60.0, f"100k LOC scan exceeded 60s target: {mean_duration:.2f}s"


@pytest.mark.perf
@pytest.mark.benchmark
def test_peak_memory_500k_loc(tmp_path: Path) -> None:
    """Assert peak memory during 500k LOC scan remains under 2 GB per docs/22-testing NFR target."""
    proj_root = tmp_path / "app_500k"
    generate_synthetic_app(proj_root, file_count=500, lines_per_file=1000)

    workspace = Workspace.open(proj_root)
    stats = WalkStats()
    project = load_project(workspace.root, stats)
    findings = scan_project(project, stats)
    assert len(findings) == 0

    peak_rss_mb = get_peak_rss_mb()
    # 2 GB limit = 2048 MB
    assert peak_rss_mb <= 2048.0, f"500k LOC scan exceeded 2 GB target: {peak_rss_mb:.1f} MB"
