from pathlib import Path

from vigilloo.graph import load_project


def test_resolve(tmp_path: Path):
    """resolve_class_name follows a `use` import alias to its fully qualified name."""
    path = tmp_path / "app/Jobs/ProcessOrder.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("""<?php
namespace App\\Jobs;
use Illuminate\\Support\\Facades\\DB;
class ProcessOrder {}
""")
    project = load_project(tmp_path)
    rel_path = Path("app/Jobs/ProcessOrder.php")
    resolved = project.resolve_class_name(rel_path, "DB")
    assert resolved == "Illuminate\\Support\\Facades\\DB"
