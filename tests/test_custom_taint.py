from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.taint import find_taint_paths


def _custom_project(
    tmp_path: Path, controller_body: str, sink_call: str, vigilloo_yaml: str
) -> Path:
    """A tiny routed controller -> repository project with a custom vigilloo.yml"""
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "app" / "Repositories").mkdir(parents=True)
    (tmp_path / "app" / "Support").mkdir(parents=True)
    (tmp_path / ".vigilloo").mkdir(parents=True)

    (tmp_path / "vigilloo.yml").write_text(vigilloo_yaml)

    (tmp_path / "routes" / "api.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\ThingController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::post('/things', [ThingController::class, 'act']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "ThingController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use App\\Repositories\\ThingRepository;\n"
        "use Illuminate\\Http\\Request;\n"
        "use App\\Support\\LegacyInput;\n"
        "class ThingController\n"
        "{\n"
        "    public function __construct(private ThingRepository $things)\n"
        "    {\n"
        "    }\n"
        "    public function act(Request $request)\n"
        "    {\n"
        f"{controller_body}\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "app" / "Repositories" / "ThingRepository.php").write_text(
        "<?php\n"
        "namespace App\\Repositories;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "class ThingRepository\n"
        "{\n"
        "    public function search(string $sort)\n"
        "    {\n"
        f"        return {sink_call};\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "app" / "Support" / "LegacyInput.php").write_text(
        "<?php\n"
        "namespace App\\Support;\n"
        "class LegacyInput\n"
        "{\n"
        "    public static function get($key) { return null; }\n"
        "    public function get_instance($key) { return null; }\n"
        "}\n"
    )
    (tmp_path / "app" / "Support" / "Helpers.php").write_text(
        "<?php\nnamespace App\\Support;\nfunction my_custom_clean($val) { return $val; }\n"
    )
    return tmp_path


def test_custom_source_static(tmp_path: Path):
    yaml = """
taint:
  sources:
    - fqn: "App\\\\Support\\\\LegacyInput::get"
      kinds: [sql]
"""
    root = _custom_project(
        tmp_path,
        "        $x = LegacyInput::get('sort');\n        $this->things->search($x);",
        "DB::table('things')->orderByRaw($sort)",
        yaml,
    )
    project = load_project(root)
    paths = find_taint_paths(project)

    assert len(paths) == 1
    steps = paths[0]
    # entry -> source -> pass -> ... -> pass -> sink
    source_step = steps[1]
    assert source_step.role == "source"
    assert "LegacyInput::get" in source_step.snippet


def test_custom_source_instance(tmp_path: Path):
    yaml = """
taint:
  sources:
    - fqn: "App\\\\Support\\\\LegacyInput::get_instance"
      kinds: [sql]
"""
    root = _custom_project(
        tmp_path,
        "        $input = new \\App\\Support\\LegacyInput();\n"
        "        $x = $input->get_instance('sort');\n"
        "        $this->things->search($x);",
        "DB::table('things')->orderByRaw($sort)",
        yaml,
    )
    project = load_project(root)
    paths = find_taint_paths(project)

    assert len(paths) == 1
    steps = paths[0]
    source_step = steps[1]
    assert source_step.role == "source"
    assert "->get_instance" in source_step.snippet


def test_custom_sanitizer_function(tmp_path: Path):
    yaml = """
taint:
  sanitizers:
    - fqn: "App\\\\Support\\\\my_custom_clean"
      clears: [sql]
"""
    root = _custom_project(
        tmp_path,
        "        $x = $request->input('sort');\n"
        "        $x = \\App\\Support\\my_custom_clean($x);\n"
        "        $this->things->search($x);",
        "DB::table('things')->orderByRaw($sort)",
        yaml,
    )
    project = load_project(root)
    paths = find_taint_paths(project)

    # Should be cleared by my_custom_clean
    assert len(paths) == 0


def test_custom_sanitizer_static(tmp_path: Path):
    yaml = """
taint:
  sanitizers:
    - fqn: "App\\\\Support\\\\LegacyInput::get"
      clears: [sql]
"""
    root = _custom_project(
        tmp_path,
        "        $x = $request->input('sort');\n"
        "        $x = LegacyInput::get($x);\n"
        "        $this->things->search($x);",
        "DB::table('things')->orderByRaw($sort)",
        yaml,
    )
    project = load_project(root)
    paths = find_taint_paths(project)

    assert len(paths) == 0
