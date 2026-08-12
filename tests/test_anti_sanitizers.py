from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import SQL_INJECTION
from vigilloo.taint import find_taint_paths


def _minimal_project(tmp_path: Path, view_body: str) -> Path:
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)

    (tmp_path / "routes" / "web.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\MyController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::post('/test', [MyController::class, 'act']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "MyController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "class MyController\n"
        "{\n"
        f"{view_body}\n"
        "}\n"
    )

    return tmp_path


def test_positive_anti_sanitizers_addslashes(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $name = addslashes($request->input('name'));
            DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == SQL_INJECTION.id

    # Assert that the path contains the anti-sanitizer step with the "weak control" note
    anti_steps = [step for step in paths[0] if step.role == "sanitizer"]
    assert len(anti_steps) == 1
    assert anti_steps[0].note == "weak control"
    assert "addslashes" in anti_steps[0].snippet


def test_positive_anti_sanitizers_strip_tags(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $name = strip_tags($request->input('name'));
            DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == SQL_INJECTION.id

    anti_steps = [step for step in paths[0] if step.role == "sanitizer"]
    assert len(anti_steps) == 1
    assert anti_steps[0].note == "weak control"
    assert "strip_tags" in anti_steps[0].snippet


def test_positive_anti_sanitizers_mysql_real_escape_string(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $name = mysql_real_escape_string($request->input('name'));
            DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == SQL_INJECTION.id

    anti_steps = [step for step in paths[0] if step.role == "sanitizer"]
    assert len(anti_steps) == 1
    assert anti_steps[0].note == "weak control"
    assert "mysql_real_escape_string" in anti_steps[0].snippet
