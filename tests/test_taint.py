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
    # Selected by sink rather than by list position: the fixture grows with
    # every slice, and an index would silently start asserting about a
    # different path.
    sql = next(p for p in paths if p[-1].span.file.name == "OrderRepository.php")

    roles = [step.role for step in sql]
    assert roles == ["entry", "source", "propagator", "sink"]

    entry, source, propagator, sink = sql
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


def test_taint_reaches_an_inherited_method(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\Child;\nRoute::post('/child', [Child::class, 'entry']);\n"
    )
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "class Base {\n"
        "  public function dangerous($value) { return DB::raw($value); }\n"
        "}\n"
        "class Child extends Base {\n"
        "  public function entry($request) { return $this->dangerous($request->input('x')); }\n"
        "}\n"
    )

    paths = find_taint_paths(load_project(tmp_path))
    assert len(paths) == 1
    assert paths[0][-1].span.start_line == 5


def test_taint_reaches_a_trait_method(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\Child;\nRoute::post('/child', [Child::class, 'entry']);\n"
    )
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "trait Dangerous {\n"
        "  public function dangerous($value) { return DB::raw($value); }\n"
        "}\n"
        "class Child {\n"
        "  use Dangerous;\n"
        "  public function entry($request) { return $this->dangerous($request->input('x')); }\n"
        "}\n"
    )

    paths = find_taint_paths(load_project(tmp_path))
    assert len(paths) == 1
    assert paths[0][-1].span.start_line == 5


def test_trait_body_dispatches_this_to_the_consuming_class(tmp_path: Path) -> None:
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\Child;\nRoute::post('/child', [Child::class, 'entry']);\n"
    )
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "trait Delegates {\n"
        "  public function delegate($value) { return $this->dangerous($value); }\n"
        "}\n"
        "class Child {\n"
        "  use Delegates;\n"
        "  public function entry($request) { return $this->delegate($request->input('x')); }\n"
        "  public function dangerous($value) { return DB::raw($value); }\n"
        "}\n"
    )

    paths = find_taint_paths(load_project(tmp_path))
    assert len(paths) == 1
    assert paths[0][-1].span.start_line == 10


def test_a_sink_is_found_when_two_declarations_share_a_line(tmp_path: Path) -> None:
    """Locating a body by its first line alone walks whichever method shares that line.

    The walk then finds nothing and counts the call as resolved, so the report says 100%
    coverage and no finding - the exact shape of a silent false negative that invariant 4
    exists to prevent.
    """
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\Child;\nRoute::post('/child', [Child::class, 'entry']);\n"
    )
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\nnamespace App;\nuse Illuminate\\Support\\Facades\\DB;\n"
        "trait T { public function helper($v) { return $v; } } "
        "class Child { use T; "
        "public function entry($request) { return DB::raw($request->input('x')); } }\n"
    )

    paths = find_taint_paths(load_project(tmp_path))
    assert len(paths) == 1
    assert "DB::raw" in paths[0][-1].snippet


def test_late_static_binding_reaches_an_override(tmp_path: Path) -> None:
    """`static::` names the runtime class, so the subclass's sink is the one that runs.

    `self::` in the same position would stay on the base and reach the safe helper, which
    is why the two are resolved differently rather than treated as synonyms.
    """
    (tmp_path / "routes").mkdir()
    (tmp_path / "app").mkdir()
    (tmp_path / "routes" / "api.php").write_text(
        "<?php\nuse App\\Child;\nRoute::post('/child', [Child::class, 'entry']);\n"
    )
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "use Illuminate\\Support\\Facades\\DB;\n"
        "class Base {\n"
        "  public function entry($request) { return static::handle($request->input('x')); }\n"
        "  public static function handle($v) { return $v; }\n"
        "}\n"
        "class Child extends Base {\n"
        "  public static function handle($v) { return DB::raw($v); }\n"
        "}\n"
    )

    paths = find_taint_paths(load_project(tmp_path))
    assert len(paths) == 1
    assert paths[0][-1].span.start_line == 9


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


def test_eloquent_get_result_without_a_request_is_not_treated_as_a_source(
    tmp_path: Path,
) -> None:
    """get(), all(), query() etc. are also Eloquent/Collection methods. Only a
    Request receiver makes them attacker-controlled data (finding 2)."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "resources" / "views" / "orders").mkdir(parents=True)

    (tmp_path / "routes" / "api.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\OrderController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/orders', [OrderController::class, 'index']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "OrderController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "class OrderController\n"
        "{\n"
        "    public function index()\n"
        "    {\n"
        "        $orders = Order::where('status', 'paid')->get();\n"
        "\n"
        "        return view('orders.show', compact('orders'));\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "resources" / "views" / "orders" / "show.blade.php").write_text(
        "<p>{!! $orders !!}</p>\n"
    )
    assert find_taint_paths(load_project(tmp_path)) == []


def test_request_receiver_still_produces_a_finding(tmp_path: Path) -> None:
    """The finding 2 fix must not overcorrect: a genuine request-receiver
    source call into a raw echo is still reported. Uses ->get(), one of the
    ambiguous names, on an actual $request to prove the receiver check (not
    the method name) is what is doing the work."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "resources" / "views" / "orders").mkdir(parents=True)

    (tmp_path / "routes" / "api.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\OrderController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/orders', [OrderController::class, 'index']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "OrderController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "class OrderController\n"
        "{\n"
        "    public function index(Request $request)\n"
        "    {\n"
        "        $sort = $request->get('sort');\n"
        "\n"
        "        return view('orders.show', compact('sort'));\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "resources" / "views" / "orders" / "show.blade.php").write_text(
        "<p>{!! $sort !!}</p>\n"
    )
    assert len(find_taint_paths(load_project(tmp_path))) == 1


def test_tainted_data_into_a_blade_loop_is_an_honest_gap(tmp_path: Path) -> None:
    """@foreach is inert text to the Blade rewriter, so $row inside the loop
    is never aliased to $rows's taint. Silence would be a false negative;
    the walk must at least say it gave up (finding 3)."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "resources" / "views" / "orders").mkdir(parents=True)

    (tmp_path / "routes" / "api.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\OrderController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::get('/orders', [OrderController::class, 'index']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "OrderController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "class OrderController\n"
        "{\n"
        "    public function index(Request $request)\n"
        "    {\n"
        "        $rows = $request->input('rows');\n"
        "\n"
        "        return view('orders.list', compact('rows'));\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "resources" / "views" / "orders" / "list.blade.php").write_text(
        "@foreach ($rows as $row)\n  <li>{!! $row !!}</li>\n@endforeach\n"
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

    Lines 3 and 4 of the fixture template render the same tainted value
    through {{ }} and through {!! e() !!}. Only line 4 actually exercises
    kind-based taint: e($sort) reaches a sink with the html kind cleared.
    Line 3's {{ $sort }} is rewritten into `e($sort);`, an expression
    statement rather than an echo (see laravel/blade.py), so it never
    becomes an echo sink at all and would stay silent even under a boolean
    taint flag.
    """
    paths = find_taint_paths(load_project(FIXTURE))
    lines = {p[-1].span.start_line for p in paths if p[-1].span.file.name == "show.blade.php"}
    assert lines == {2}


def test_inline_source_reaches_the_sink_without_a_variable(tmp_path: Path) -> None:
    """whereRaw($request->input('sort')) with no intermediate assignment.

    Source recognition used to live only in the assignment branch, so the most
    idiomatic form of the call - the one with nothing stored in a variable -
    produced no finding at all.
    """
    project_root = _minimal_project(
        tmp_path,
        controller_body=('        return DB::table("t")->orderByRaw($request->input("sort"));'),
        sink_call='DB::table("t")->orderBy("created_at")',
    )
    paths = find_taint_paths(load_project(project_root))
    assert len(paths) == 1
    assert paths[0][-1].role == "sink"
    assert "orderByRaw" in paths[0][-1].snippet


def test_only_the_matched_rule_is_named_on_the_sink_step() -> None:
    """rules.py dispatches on this string, not on the sink's file extension."""
    by_file = {p[-1].span.file.name: p[-1].rule_id for p in find_taint_paths(load_project(FIXTURE))}
    assert by_file["OrderRepository.php"] == "php.sql-injection"
    assert by_file["show.blade.php"] == "php.xss"
