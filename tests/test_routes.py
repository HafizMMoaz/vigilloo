from pathlib import Path

from vigilloo.laravel.routes import discover_route_files, extract_routes
from vigilloo.parser import collect_nodes, parse_php, parse_source
from vigilloo.symbols import extract_symbols

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_extracts_routes_with_resolved_action() -> None:
    parsed = parse_php(FIXTURE / "routes/api.php")
    routes = extract_routes(
        parsed,
        extract_symbols(
            collect_nodes(parsed.tree.root_node).namespaces,
            collect_nodes(parsed.tree.root_node).imports,
            collect_nodes(parsed.tree.root_node).classes,
            collect_nodes(parsed.tree.root_node).traits,
            parsed,
        ),
    )
    by_uri = {r.uri: r for r in routes}

    assert set(by_uri) >= {"/orders/search", "/orders/recent", "/orders/display"}
    search = by_uri["/orders/search"]
    assert search.verbs == ("POST",)
    assert search.action_fqn == "App\\Http\\Controllers\\OrderController::search"

    # Derived rather than hardcoded: the span has to point at the registration,
    # and a literal line number only records where the fixture happened to put
    # it last time someone edited the file.
    lines = (FIXTURE / "routes/api.php").read_text().splitlines()
    assert lines[search.span.start_line - 1].startswith("Route::post('/orders/search'")


def _middleware(php: str) -> dict[str, tuple[str, ...]]:
    parsed = parse_source(Path("routes/api.php"), php.encode())
    return {
        r.uri: r.middleware
        for r in extract_routes(
            parsed,
            extract_symbols(
                collect_nodes(parsed.tree.root_node).namespaces,
                collect_nodes(parsed.tree.root_node).imports,
                collect_nodes(parsed.tree.root_node).classes,
                collect_nodes(parsed.tree.root_node).traits,
                parsed,
            ),
        )
    }


def test_middleware_is_collected_from_the_chain_and_the_enclosing_group() -> None:
    """Route::get(...) is the *object* of ->middleware(...), not its caller.

    So middleware is found by walking up from the registration. The group form
    continues that walk out through the closure, which is how most real route
    files apply auth.
    """
    found = _middleware("""<?php
Route::get('/a/{a}', [C::class, 'show'])->middleware('auth');
Route::get('/b/{b}', [C::class, 'show'])->middleware(['auth', 'can:view,b'])->name('b');
Route::get('/c/{c}', [C::class, 'show'])->middleware('auth')->middleware('signed');
Route::middleware(['auth'])->group(function () {
    Route::get('/d/{d}', [C::class, 'show']);
    Route::get('/e/{e}', [C::class, 'show'])->middleware('can:view,e');
});
Route::get('/f', [C::class, 'show']);
""")
    assert found == {
        "/a/{a}": ("auth",),
        "/b/{b}": ("auth", "can:view,b"),
        # Two chained calls start at the same byte; collapsing them would drop
        # one silently.
        "/c/{c}": ("auth", "signed"),
        "/d/{d}": ("auth",),
        "/e/{e}": ("auth", "can:view,e"),
        "/f": (),
    }


def test_middleware_that_is_not_a_literal_is_marked_unresolved() -> None:
    """Dropping it would turn "I cannot read this" into "there is nothing here".

    An authorization rule reading the result would then report a guarded route.
    """
    found = _middleware("""<?php
Route::get('/a/{a}', [C::class, 'show'])->middleware('auth')->middleware($extra);
Route::get('/b/{b}', [C::class, 'show'])->middleware([self::ADMIN]);
""")
    assert found == {"/a/{a}": ("auth", "?"), "/b/{b}": ("?",)}


def test_routes_are_returned_in_deterministic_order() -> None:
    parsed = parse_php(FIXTURE / "routes/api.php")
    symbols = extract_symbols(
        collect_nodes(parsed.tree.root_node).namespaces,
        collect_nodes(parsed.tree.root_node).imports,
        collect_nodes(parsed.tree.root_node).classes,
        collect_nodes(parsed.tree.root_node).traits,
        parsed,
    )
    assert extract_routes(parsed, symbols) == extract_routes(parsed, symbols)


def test_discover_route_files() -> None:
    fixture_path = Path("tests/fixtures/task-038-routes")
    files = {}
    for php_file in fixture_path.rglob("*.php"):
        rel_path = php_file.relative_to(fixture_path)
        parsed = parse_source(rel_path, php_file.read_bytes())
        files[rel_path] = parsed

    discovered = discover_route_files(files)

    assert Path("routes/api/v1.php") in discovered
    assert Path("routes/web.php") in discovered
    assert Path("custom/routes.php") in discovered
    assert Path("routes/console.php") in discovered
    assert Path("routes/channels.php") in discovered
    assert Path("routes/api.php") in discovered


def test_groups_and_resources() -> None:
    p = Path("tests/fixtures/task-039-routes/routes/web.php")
    parsed = parse_source(p, p.read_bytes())
    symbols = extract_symbols(
        collect_nodes(parsed.tree.root_node).namespaces,
        collect_nodes(parsed.tree.root_node).imports,
        collect_nodes(parsed.tree.root_node).classes,
        collect_nodes(parsed.tree.root_node).traits,
        parsed,
    )
    routes = extract_routes(parsed, symbols)

    # Let's verify the extracted routes.
    # 1. /home
    # 2. /admin/dashboard
    # 3. /admin/users/create
    # 4. /admin/users/{user}
    # 5-11. /posts (resource, 7 routes)
    # 12-16. /items (apiResource, 5 routes)
    assert len(routes) == 16

    # 2. admin dashboard
    r = next(r for r in routes if r.uri == "/admin/dashboard")
    assert r.middleware == ("auth", "verified")

    # 4. admin user show
    r = next(r for r in routes if r.uri == "/admin/users/{user}")
    assert r.middleware == ("auth", "verified", "can:manage-users", "throttle:60,1")

    # 5-11. resource: posts index
    r = next(r for r in routes if r.uri == "/posts" and "GET" in r.verbs)
    assert r.middleware == ("api",)
    assert r.action_fqn == "App\\Http\\Controllers\\PostController::index"

    # resource: posts store
    r = next(r for r in routes if r.uri == "/posts" and "POST" in r.verbs)
    assert r.action_fqn == "App\\Http\\Controllers\\PostController::store"

    # resource: posts show
    r = next(r for r in routes if r.uri == "/posts/{post}" and "GET" in r.verbs)
    assert r.action_fqn == "App\\Http\\Controllers\\PostController::show"

    # resource: posts update
    r = next(r for r in routes if r.uri == "/posts/{post}" and "PUT" in r.verbs)
    assert r.action_fqn == "App\\Http\\Controllers\\PostController::update"


def test_dynamic_routes_are_recorded_with_low_confidence() -> None:
    parsed = parse_source(
        Path("routes/api.php"),
        b"""<?php
Route::get($var, [C::class, 'show']);
Route::resource($dynamic, C::class);
foreach ($items as $item) {
    Route::post('/api/' . $item, [C::class, 'store']);
}
""",
    )
    symbols = extract_symbols(
        collect_nodes(parsed.tree.root_node).namespaces,
        collect_nodes(parsed.tree.root_node).imports,
        collect_nodes(parsed.tree.root_node).classes,
        collect_nodes(parsed.tree.root_node).traits,
        parsed,
    )
    routes = extract_routes(parsed, symbols)

    assert len(routes) == 9

    # $var and $dynamic become {dynamic}
    dyn_get = next(r for r in routes if "GET" in r.verbs and r.action_fqn == "C::show")
    assert dyn_get.uri == "/{dynamic}"
    assert dyn_get.confidence == 0.5

    # foreach loop
    dyn_post = next(r for r in routes if "POST" in r.verbs and r.action_fqn == "C::store")
    assert dyn_post.uri == "/{dynamic}"
    assert dyn_post.confidence == 0.5
