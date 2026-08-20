#!/usr/bin/env python3
"""Benchmark harness to measure Vigilloo scan performance.

Usage: uv run python scripts/benchmark.py <path-to-project>
"""

import argparse
import resource
import sys
import time
from pathlib import Path

# Add src to python path so we can import vigilloo modules
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

from src import __version__
from src.graph import load_project
from src.models import WalkStats
from src.report import build_document
from src.rules import RULESET_HASH, scan_project
from src.workspace import Workspace


def get_peak_rss_mb() -> float:
    """Returns peak RSS in MB."""
    # resource.getrusage returns bytes on macOS, kilobytes on Linux.
    # Assuming macOS since this is Apple/Projects...
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return usage / (1024 * 1024)
    else:
        return usage / 1024


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Vigilloo scan.")
    parser.add_argument("path", type=Path, help="Path to project to scan")
    args = parser.parse_args()

    target = args.path.resolve()
    if not target.is_dir():
        print(f"Error: {target} is not a directory.")
        sys.exit(1)

    print(f"Benchmarking scan of {target}...")

    stages = {}

    t0 = time.perf_counter()

    # 1. Workspace open
    t_start = time.perf_counter()
    workspace = Workspace.open(target)
    stages["workspace"] = time.perf_counter() - t_start

    # 2. Graph/Parse
    t_start = time.perf_counter()
    stats = WalkStats()
    project = load_project(workspace.root, stats)
    stages["load_project (parse/enrich/graph)"] = time.perf_counter() - t_start

    if not project.files and not project.failed:
        print("No PHP files found.")
        sys.exit(0)

    # 3. Analyse
    t_start = time.perf_counter()
    findings = scan_project(project, stats, baseline=None)
    stages["analyse"] = time.perf_counter() - t_start

    # 4. Report
    t_start = time.perf_counter()
    from src.graph import coverage

    scan_coverage = coverage(project, stats)
    build_document(findings, scan_coverage, engine_version=__version__, ruleset_hash=RULESET_HASH)
    stages["report"] = time.perf_counter() - t_start

    total_time = time.perf_counter() - t0
    peak_rss = get_peak_rss_mb()

    print("\n--- Benchmark Results ---")
    print(f"Total files: {len(project.files)}")
    print(f"Findings: {len(findings)}")
    print(f"Peak RSS: {peak_rss:.1f} MB")
    print(f"Total Wall Time: {total_time:.3f} s")
    print("\nPer-Stage Breakdown:")
    for stage, duration in stages.items():
        print(f"  {stage:30}: {duration:.3f} s ({duration / total_time * 100:.1f}%)")


if __name__ == "__main__":
    main()
