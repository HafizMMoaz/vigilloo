from pathlib import Path

from vigilloo.laravel.middleware import extract_middleware_groups
from vigilloo.parser import parse_php


def test_parse_kernel_groups():
    path = Path("tests/fixtures/task-041-middleware/app/Http/Kernel.php")
    parsed = parse_php(path)
    groups = extract_middleware_groups(parsed)
    
    assert "web" in groups
    assert "api" in groups
    assert len(groups["web"]) == 6
    assert groups["web"][0] == "App\\Http\\Middleware\\EncryptCookies"
    assert len(groups["api"]) == 2
    assert groups["api"][0] == "throttle:api"
    assert groups["api"][1] == "Illuminate\\Routing\\Middleware\\SubstituteBindings"

def test_parse_app_groups():
    path = Path("tests/fixtures/task-041-middleware/bootstrap/app.php")
    parsed = parse_php(path)
    groups = extract_middleware_groups(parsed)
    
    assert "web" in groups
    assert "api" in groups
    assert len(groups["web"]) == 2
    assert len(groups["api"]) == 3
    assert (
        groups["api"][0]
        == "Laravel\\Sanctum\\Http\\Middleware\\EnsureFrontendRequestsAreStateful"
    )
    assert groups["api"][1] == "throttle:api"
    assert groups["api"][2] == "Illuminate\\Routing\\Middleware\\SubstituteBindings"
