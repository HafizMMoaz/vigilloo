from pathlib import Path

from vigilloo.graph import Project
from vigilloo.laravel.middleware import (
    extract_middleware_groups,
    is_authenticated,
    is_gated,
    is_guest,
    is_password_confirmed,
    is_rate_limited,
    is_signed,
    is_verified,
    middleware_sanitizes,
)
from vigilloo.models import Route
from vigilloo.parser import parse_php, parse_source
from vigilloo.symbols import extract_symbols


def test_parse_kernel_groups() -> None:
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


def test_parse_app_groups() -> None:
    path = Path("tests/fixtures/task-041-middleware/bootstrap/app.php")
    parsed = parse_php(path)
    groups = extract_middleware_groups(parsed)

    assert "web" in groups
    assert "api" in groups
    assert len(groups["web"]) == 2
    assert len(groups["api"]) == 3
    assert (
        groups["api"][0] == "Laravel\\Sanctum\\Http\\Middleware\\EnsureFrontendRequestsAreStateful"
    )
    assert groups["api"][1] == "throttle:api"
    assert groups["api"][2] == "Illuminate\\Routing\\Middleware\\SubstituteBindings"


def test_middleware_semantics() -> None:
    assert is_authenticated(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )
    assert is_authenticated(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth:sanctum"])
    )
    assert not is_authenticated(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["guest"])
    )

    assert is_guest(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["guest"])
    )
    assert not is_guest(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )

    assert is_verified(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["verified"])
    )
    assert not is_verified(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )

    assert is_signed(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["signed"])
    )
    assert not is_signed(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )

    assert is_rate_limited(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["throttle:60,1"])
    )
    assert not is_rate_limited(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )

    project = Project(root=Path("."))
    assert is_gated(
        project,
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["can:view,model"]),
    )
    assert is_gated(
        project, Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["?"])
    )
    assert not is_gated(
        project, Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )

    assert is_password_confirmed(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["password.confirm"])
    )
    assert not is_password_confirmed(
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["auth"])
    )


def test_trim_strings_does_not_sanitize() -> None:
    assert middleware_sanitizes("TrimStrings") == frozenset()
    assert (
        middleware_sanitizes("Illuminate\\Foundation\\Http\\Middleware\\TrimStrings") == frozenset()
    )
    assert middleware_sanitizes("ConvertEmptyStringsToNull") == frozenset()
    assert (
        middleware_sanitizes("Illuminate\\Foundation\\Http\\Middleware\\ConvertEmptyStringsToNull")
        == frozenset()
    )


def test_custom_middleware_gating() -> None:
    code = b"""<?php
    class GateMiddleware {
        public function handle() {
            abort(403);
        }
    }
    class RedirectMiddleware {
        public function handle() {
            return redirect('/login');
        }
    }
    class SafeMiddleware {
        public function handle() {
            return $next($request);
        }
    }
    """
    path = Path("test.php")
    parsed = parse_source(path, code)
    symbols = extract_symbols(parsed)
    project = Project(root=Path("."), files={path: parsed}, classes=symbols.classes)

    assert is_gated(
        project,
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["GateMiddleware"]),
    )
    assert is_gated(
        project,
        Route(
            uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["RedirectMiddleware"]
        ),
    )
    assert not is_gated(
        project,
        Route(uri="/", verbs=["GET"], span=None, action_fqn="A::b", middleware=["SafeMiddleware"]),
    )
