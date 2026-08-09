from pathlib import Path

from vigilloo.graph import Project
from vigilloo.laravel.facades import BUILTIN_FACADES, resolve_facade
from vigilloo.taint import WalkStats, find_taint_paths


def test_builtin_facades_resolve_to_concrete_classes(tmp_path: Path) -> None:
    """Every built-in facade mapped in docs/07-call-graph resolves to its concrete class."""
    project = Project(root=tmp_path, files={}, autoload=None)
    for facade, concrete in BUILTIN_FACADES.items():
        assert resolve_facade(facade, project) == concrete


def test_real_time_facades_resolve_by_stripping_prefix(tmp_path: Path) -> None:
    """Facades\\App\\Services\\Foo resolves to App\\Services\\Foo."""
    project = Project(root=tmp_path, files={}, autoload=None)
    assert resolve_facade("Facades\\App\\Services\\Foo", project) == "App\\Services\\Foo"


def test_unknown_facades_are_not_guessed(tmp_path: Path) -> None:
    """An unknown facade name returns None, leaving it for the unresolved call counter."""
    project = Project(root=tmp_path, files={}, autoload=None)
    assert resolve_facade("Illuminate\\Support\\Facades\\Unknown", project) is None


def test_app_aliases_resolve_facades(tmp_path: Path) -> None:
    """config/app.php's aliases array maps global names to facades."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "app.php").write_text(
        "<?php\n"
        "return [\n"
        "    'aliases' => [\n"
        "        'App' => Illuminate\\Support\\Facades\\App::class,\n"
        "        'Auth' => Illuminate\\Support\\Facades\\Auth::class,\n"
        "        'Custom' => App\\Facades\\Custom::class,\n"
        "        'StringAlias' => 'App\\\\Facades\\\\StringAlias',\n"
        "    ],\n"
        "];\n"
    )
    project = Project(root=tmp_path, files={}, autoload=None)

    # Auth is a builtin facade, so the alias should recursively resolve to AuthManager
    assert resolve_facade("Auth", project) == BUILTIN_FACADES["Illuminate\\Support\\Facades\\Auth"]

    # Custom isn't a builtin facade, so it resolves to the aliased facade class
    assert resolve_facade("Custom", project) == "App\\Facades\\Custom"

    # StringAlias is passed as string instead of ::class
    assert resolve_facade("StringAlias", project) == "App\\Facades\\StringAlias"


def test_unknown_facades_increment_unresolved_count(tmp_path: Path) -> None:
    """A call on an unknown facade is recorded as an unresolved call."""
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)
    (tmp_path / "routes" / "web.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\FooController;\n"
        "Route::post('/test', [FooController::class, 'act']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "FooController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "use Illuminate\\Support\\Facades\\UnknownFacade;\n"
        "class FooController\n"
        "{\n"
        "    public function act(Request $request)\n"
        "    {\n"
        "        // UnknownFacade does not resolve to a concrete class, and we don't have its\n"
        "        // source, so this method call is unresolved.\n"
        "        UnknownFacade::doSomething($request->input('x'));\n"
        "    }\n"
        "}\n"
    )
    from vigilloo.graph import load_project

    project = load_project(tmp_path)
    stats = WalkStats()
    find_taint_paths(project, stats=stats)

    # $request->input is a source, so it's resolved.
    # UnknownFacade::doSomething gets tainted input, and because UnknownFacade
    # isn't known and has no source, it counts as an unresolved call losing taint.
    assert stats.unresolved == 1
