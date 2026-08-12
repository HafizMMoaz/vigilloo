from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import OPEN_REDIRECT
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
        "use Illuminate\\Support\\Facades\\Redirect;\n"
        "class MyController\n"
        "{\n"
        f"{view_body}\n"
        "}\n"
    )

    return tmp_path


def test_positive_open_redirect(tmp_path: Path):
    body = """
        public function act(Request $request) {
            return redirect($request->input('next'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == OPEN_REDIRECT.id


def test_positive_header_injection(tmp_path: Path):
    body = """
        public function act(Request $request) {
            header("Location: " . $request->input('next'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == OPEN_REDIRECT.id


def test_positive_response_header(tmp_path: Path):
    body = """
        public function act(Request $request) {
            return \\Illuminate\\Support\\Facades\\Response::header('X-Custom', $request->input('next'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == OPEN_REDIRECT.id


def test_negative_allowlist_redirect(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $data = $request->validate([
                'next' => 'in:/home,/dashboard',
            ]);
            return redirect($data['next']);
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 0


def test_negative_relative_path_redirect(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $data = $request->validate([
                'next' => 'starts_with:/',
            ]);
            return redirect($data['next']);
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 0


def test_positive_redirect_facade(tmp_path: Path):
    body = """
        public function act(Request $request) {
            Redirect::to($request->input('next'));
            Redirect::away($request->input('next'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 2
    assert paths[0][-1].rule_id == OPEN_REDIRECT.id
    assert paths[1][-1].rule_id == OPEN_REDIRECT.id
