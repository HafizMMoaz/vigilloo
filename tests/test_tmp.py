from pathlib import Path

from vigilloo.graph import load_project


def _write_files(base_dir: Path, files: dict[str, str]) -> None:
    for rel_path, content in files.items():
        path = base_dir / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def test_job(tmp_path: Path) -> None:
    files = {
        "app/Jobs/ProcessOrder.php": """
        <?php
        namespace App\\Jobs;
        use Illuminate\\Support\\Facades\\DB;
        class ProcessOrder {
            public $orderId;
            public function handle() {
                $tainted = $this->orderId;
                DB::select("SELECT " . $tainted);
            }
        }
        """
    }
    _write_files(tmp_path, files)
    project = load_project(tmp_path)

    from vigilloo.taint import find_taint_paths

    paths = find_taint_paths(project)
    print("Found paths:", len(paths))
    for p in paths:
        print(p)
