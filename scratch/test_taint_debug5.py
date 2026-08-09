import sys
from vigilloo.graph import load_project
from vigilloo.taint import WalkStats, find_taint_paths, _follow_static
import vigilloo.taint as taint_mod

orig_follow_static = taint_mod._follow_static
def patched_follow_static(*args, **kwargs):
    print(f"follow_static receiver={args[2]} args={args[4]}")
    res = orig_follow_static(*args, **kwargs)
    return res
taint_mod._follow_static = patched_follow_static

from pathlib import Path
project = load_project(Path('scratch/tmp3'))
stats = WalkStats()
find_taint_paths(project, stats=stats)
print("Unresolved:", stats.unresolved)
