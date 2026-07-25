from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.models import WalkStats
from vigilloo.taint import find_taint_paths

FIXTURE = Path("tests/fixtures/laravel-minimal")


def _minimal_project(tmp_path: Path, controller_body: str, sink_call: str) -> Path:
    """A tiny routed controller -> repository project, body and sink swappable."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "app" / "Repositories").mkdir(parents=True)

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
    return tmp_path


def test_finds_the_interprocedural_path_to_the_sink() -> None:
    paths = find_taint_paths(load_project(FIXTURE))
    assert len(paths) == 2

    roles = [step.role for step in paths[0]]
    assert roles == ["entry", "source", "propagator", "sink"]

    entry, source, propagator, sink = paths[0]
    assert "/orders/search" in entry.snippet
    assert "input" in source.snippet
    assert source.span.start_line == 17
    assert propagator.span.start_line == 19
    assert "orderByRaw" in sink.snippet
    assert sink.span.file.name == "OrderRepository.php"
    assert sink.span.start_line == 12


def test_safe_action_produces_no_path() -> None:
    """The recent() action uses a bound orderBy and must stay silent."""
    paths = find_taint_paths(load_project(FIXTURE))
    assert all("recent" not in step.snippet for path in paths for step in path)


def test_paths_are_deterministic() -> None:
    project = load_project(FIXTURE)
    assert find_taint_paths(project) == find_taint_paths(project)


def test_reassignment_to_a_constant_untaints_the_variable(tmp_path: Path) -> None:
    """$sort is overwritten with a literal before it ever reaches the sink."""
    project_root = _minimal_project(
        tmp_path,
        controller_body=(
            "        $sort = $request->input('sort');\n"
            "        $sort = 'created_at asc';\n"
            "        return $this->things->search($sort);"
        ),
        sink_call='DB::table("t")->orderByRaw("created_at {$sort}")',
    )
    assert find_taint_paths(load_project(project_root)) == []


def test_select_with_tainted_argument_produces_no_path(tmp_path: Path) -> None:
    """->select([$x]) is a safe builder call, not the raw DB::select() facade."""
    project_root = _minimal_project(
        tmp_path,
        controller_body=(
            "        $sort = $request->input('sort');\n        return $this->things->search($sort);"
        ),
        sink_call='DB::table("t")->select([$sort])',
    )
    assert find_taint_paths(load_project(project_root)) == []


def test_clean_project_reports_no_lost_trails() -> None:
    """A give-up counter that fires on correct code trains users to ignore it.

    The fixture resolves everything that matters, so nothing was lost. Benign
    unresolved receivers - the $request->input() source call, a ->get() chain
    terminator - must not be counted.
    """
    stats = WalkStats()
    find_taint_paths(load_project(FIXTURE), stats=stats)
    assert stats.unresolved == 0


def test_abandoning_a_tainted_argument_is_counted(tmp_path: Path) -> None:
    """Losing the trail on tainted data is exactly what the counter is for."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\C;\nRoute::post('/a', [C::class, 'a']);\n"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "C.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "class C\n"
        "{\n"
        "    public function a($request)\n"
        "    {\n"
        "        $sort = $request->input('sort');\n"
        "\n"
        "        return $unknown->handle($sort);\n"
        "    }\n"
        "}\n"
    )
    stats = WalkStats()
    find_taint_paths(load_project(tmp_path), stats=stats)
    assert stats.unresolved == 1


def test_computed_view_name_with_tainted_data_is_counted(tmp_path: Path) -> None:
    """view($name, ...) cannot be resolved, but losing tainted data there is a
    real gap - the walk must not go silent about it (finding 1)."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\C;\nRoute::post('/a', [C::class, 'a']);\n"
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "C.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "class C\n"
        "{\n"
        "    public function a($request)\n"
        "    {\n"
        "        $sort = $request->input('sort');\n"
        "        $name = 'orders.show';\n"
        "\n"
        "        return view($name, compact('sort'));\n"
        "    }\n"
        "}\n"
    )
    stats = WalkStats()
    find_taint_paths(load_project(tmp_path), stats=stats)
    assert stats.unresolved == 1


def test_numeric_coercion_defeats_the_sql_sink(tmp_path: Path) -> None:
    """intval() makes interpolation safe, and a boolean flag cannot see that.

    This is a false positive the slice 1 engine reports today.
    """
    project_root = _minimal_project(
        tmp_path,
        controller_body=(
            "        $sort = $request->input('sort');\n        return $this->things->search($sort);"
        ),
        sink_call='DB::table("t")->orderByRaw("age > " . intval($sort))',
    )
    assert find_taint_paths(load_project(project_root)) == []


def test_html_escaping_does_not_clear_the_sql_kind(tmp_path: Path) -> None:
    """e() is not a SQL sanitizer. Clearing sql here would be a false negative."""
    project_root = _minimal_project(
        tmp_path,
        controller_body=(
            "        $sort = $request->input('sort');\n        return $this->things->search($sort);"
        ),
        sink_call='DB::table("t")->orderByRaw("created_at " . e($sort))',
    )
    assert len(find_taint_paths(load_project(project_root))) == 1


def test_raw_blade_echo_is_reached_from_the_route() -> None:
    """The full slice 2 path: route, controller, view() call, template sink."""
    paths = find_taint_paths(load_project(FIXTURE))
    blade = [p for p in paths if p[-1].span.file.name == "show.blade.php"]

    assert len(blade) == 1
    roles = [step.role for step in blade[0]]
    assert roles == ["entry", "source", "propagator", "sink"]

    sink = blade[0][-1]
    assert sink.span.start_line == 2
    assert sink.snippet == "<p>Raw: {!! $sort !!}</p>"


def test_escaped_and_manually_escaped_echoes_are_silent() -> None:
    """The test that distinguishes a kind set from a boolean flag.

    Lines 3 and 4 of the fixture template render the same tainted value through
    {{ }} and through {!! e() !!}. Both are safe, and a boolean taint flag
    would report both.
    """
    paths = find_taint_paths(load_project(FIXTURE))
    lines = {p[-1].span.start_line for p in paths if p[-1].span.file.name == "show.blade.php"}
    assert lines == {2}
