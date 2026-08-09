import sys
from vigilloo.graph import load_project
from vigilloo.taint import WalkStats, find_taint_paths
import vigilloo.taint as taint_mod
orig_scoped_receiver = taint_mod._scoped_receiver
def patched_scoped_receiver(*args, **kwargs):
    res = orig_scoped_receiver(*args, **kwargs)
    print(f"scoped_receiver({args[1]}) -> {res}")
    return res
taint_mod._scoped_receiver = patched_scoped_receiver

orig_giveup = taint_mod._giveup
def patched_giveup(*args, **kwargs):
    print("_giveup called!")
    return orig_giveup(*args, **kwargs)
taint_mod._giveup = patched_giveup

from pathlib import Path
project = load_project(Path('scratch/tmp3'))
stats = WalkStats()
find_taint_paths(project, stats=stats)
print("Unresolved:", stats.unresolved)
