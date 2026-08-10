from pathlib import Path

from vigilloo.graph import load_project


def test_resolve(tmp_path: Path):
    path = tmp_path / "app/Jobs/ProcessOrder.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("""<?php
namespace App\\Jobs;
use Illuminate\\Support\\Facades\\DB;
class ProcessOrder {}
""")
    project = load_project(tmp_path)
    rel_path = Path("app/Jobs/ProcessOrder.php")
    res = project.resolve_class_name(rel_path, "DB")
    print("Resolved DB:", res)
