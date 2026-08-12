from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.taint import find_taint_paths


def _minimal_project(tmp_path: Path, view_body: str) -> Path:
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "resources" / "views").mkdir(parents=True)

    (tmp_path / "routes" / "api.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\ThingController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::post('/things', [ThingController::class, 'act']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "ThingController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "class ThingController\n"
        "{\n"
        "    public function act(Request $request)\n"
        "    {\n"
        "        return view('show', ['x' => $request->input('x')]);\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "resources" / "views" / "show.blade.php").write_text(view_body)
    return tmp_path


def test_js_taint_in_script_block(tmp_path: Path) -> None:
    project = load_project(_minimal_project(tmp_path, "<script>var a = {{ $x }};</script>"))
    paths = find_taint_paths(project)

    assert len(paths) == 1
    assert paths[0][-1].rule_id == "php.xss"
    assert "vigilloo_js_sink" not in paths[0][-1].snippet
    assert "{{ $x }}" in paths[0][-1].snippet


def test_safe_in_html_context(tmp_path: Path) -> None:
    # {{ $x }} is safe in HTML context
    project = load_project(_minimal_project(tmp_path, "<div>{{ $x }}</div>"))
    paths = find_taint_paths(project)
    assert len(paths) == 0


def test_raw_echo_in_html_context(tmp_path: Path) -> None:
    # {!! $x !!} is unsafe in HTML context
    project = load_project(_minimal_project(tmp_path, "<div>{!! $x !!}</div>"))
    paths = find_taint_paths(project)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == "php.xss"


def test_js_from_prevents_xss(tmp_path: Path) -> None:
    project = load_project(
        _minimal_project(tmp_path, "<script>var a = {{ Js::from($x) }};</script>")
    )
    paths = find_taint_paths(project)
    assert len(paths) == 0


def test_json_encode_with_flag_prevents_xss(tmp_path: Path) -> None:
    project = load_project(
        _minimal_project(
            tmp_path, "<script>var a = {!! json_encode($x, JSON_HEX_TAG) !!};</script>"
        )
    )
    paths = find_taint_paths(project)
    assert len(paths) == 0


def test_json_encode_without_flag_is_vulnerable(tmp_path: Path) -> None:
    project = load_project(
        _minimal_project(tmp_path, "<script>var a = {!! json_encode($x) !!};</script>")
    )
    paths = find_taint_paths(project)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == "php.xss"
