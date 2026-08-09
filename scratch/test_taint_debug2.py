from vigilloo.graph import load_project
from vigilloo.taint import WalkStats, find_taint_paths
from pathlib import Path
project = load_project(Path("scratch/tmp2"))
stats = WalkStats()
find_taint_paths(project, stats=stats)
print("Unresolved:", stats.unresolved)
