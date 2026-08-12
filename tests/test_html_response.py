from pathlib import Path

from vigilloo.rules import XSS_RULE


def _minimal_project(tmp_path: Path, view_body: str) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()

    routes = proj / "routes"
    routes.mkdir()
    (routes / "web.php").write_text(
        "<?php\nuse Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/', [App\\Http\\Controllers\\Controller::class, 'act']);"
    )

    ctrl = proj / "app" / "Http" / "Controllers"
    ctrl.mkdir(parents=True)
    (ctrl / "Controller.php").write_text(
        "<?php\nnamespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "class Controller {"
        f"    {view_body}\n"
        "}"
    )
    return proj


def test_html_response_sink(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $tainted = $request->input('name');
            return response($tainted)->header('Content-Type', 'text/html');
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    from vigilloo.graph import load_project
    from vigilloo.taint import find_taint_paths

    project = load_project(proj_dir)
    paths = find_taint_paths(project)

    assert len(paths) == 1
    assert paths[0][-1].role == "sink"
    assert paths[0][-1].rule_id == XSS_RULE


def test_json_response_not_sink(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $tainted = $request->input('name');
            return response($tainted)->header('Content-Type', 'application/json');
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    from vigilloo.graph import load_project
    from vigilloo.taint import find_taint_paths

    project = load_project(proj_dir)
    paths = find_taint_paths(project)

    assert len(paths) == 0


def test_plain_response_sink(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $tainted = $request->input('name');
            return response($tainted);
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    from vigilloo.graph import load_project
    from vigilloo.taint import find_taint_paths

    project = load_project(proj_dir)
    paths = find_taint_paths(project)

    assert len(paths) == 1
    assert paths[0][-1].role == "sink"
    assert paths[0][-1].rule_id == XSS_RULE
