from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.taint import WalkStats, find_taint_paths

tmp_path = Path("scratch/tmp2")
tmp_path.mkdir(exist_ok=True)
(tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True, exist_ok=True)
(tmp_path / "app" / "Http" / "Controllers" / "FooController.php").write_text(
    "<?php\n"
    "namespace App\\Http\\Controllers;\n"
    "use Illuminate\\Http\\Request;\n"
    "use Illuminate\\Support\\Facades\\UnknownFacade;\n"
    "class FooController\n"
    "{\n"
    "    public function act(Request $request)\n"
    "    {\n"
    "        UnknownFacade::doSomething($request->input('x'));\n"
    "    }\n"
    "}\n"
)
project = load_project(tmp_path)
stats = WalkStats()
find_taint_paths(project, stats=stats)
print(f"Unresolved: {stats.unresolved}")
