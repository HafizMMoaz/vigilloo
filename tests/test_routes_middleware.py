from pathlib import Path

from vigilloo.laravel.routes import extract_routes
from vigilloo.parser import parse_php
from vigilloo.symbols import extract_symbols

FIXTURE = Path("tests/fixtures/task-039-routes/routes/web.php")


def test_extracts_routes_with_middleware_expansion() -> None:
    parsed = parse_php(FIXTURE)

    middleware_groups = {
        "api": ["throttle:api", "bindings", "CustomApiMw"],
        "auth": ["auth_base", "api_token_check"],
    }

    routes = extract_routes(parsed, extract_symbols(parsed), None, middleware_groups)
    by_uri = {r.uri: r for r in routes}

    dashboard_route = by_uri.get("/admin/dashboard")
    assert dashboard_route is not None

    expected_admin_mw = (
        "auth_base",
        "api_token_check",  # expanded 'auth'
        "verified",  # unexpanded
    )

    assert dashboard_route.middleware == expected_admin_mw

    post_index_route = by_uri.get("/posts")
    assert post_index_route is not None

    expected_api_mw = (
        "throttle:api",
        "bindings",
        "CustomApiMw",  # expanded 'api'
    )

    assert post_index_route.middleware == expected_api_mw
