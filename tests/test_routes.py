from pathlib import Path

from vigilloo.laravel.routes import extract_routes
from vigilloo.parser import parse_php
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
    assert search.span.start_line == 8


def test_routes_are_returned_in_deterministic_order() -> None:
    parsed = parse_php(FIXTURE / "routes/api.php")
    symbols = extract_symbols(parsed)
    assert extract_routes(parsed, symbols) == extract_routes(parsed, symbols)
