from pathlib import Path

from vigilloo.laravel.routes import discover_route_files, extract_routes
from vigilloo.parser import parse_php, parse_source
from vigilloo.symbols import extract_symbols

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_extracts_routes_with_resolved_action() -> None:
    parsed = parse_php(FIXTURE / "routes/api.php")
    routes = extract_routes(parsed, extract_symbols(parsed))
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
    return {r.uri: r.middleware for r in extract_routes(parsed, extract_symbols(parsed))}


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
    symbols = extract_symbols(parsed)
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
