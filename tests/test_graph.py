from pathlib import Path

from vigilloo.graph import load_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_loads_all_php_files_and_routes() -> None:
    project = load_project(FIXTURE)
    assert len(project.routes) == 2
    assert not project.failed
    assert "App\\Http\\Controllers\\OrderController" in project.classes
    assert "App\\Repositories\\OrderRepository" in project.classes


def test_resolves_injected_property_to_class() -> None:
    """$this->orders must resolve to OrderRepository for the call graph."""
    project = load_project(FIXTURE)
    resolved = project.resolve_property_type("App\\Http\\Controllers\\OrderController", "orders")
    assert resolved == "App\\Repositories\\OrderRepository"


def test_method_lookup_by_fqn() -> None:
    project = load_project(FIXTURE)
    method = project.method("App\\Repositories\\OrderRepository::search")
    assert method is not None
    assert method.params == ("sort",)


def test_blade_templates_are_rewritten_not_parsed_as_php(tmp_path: Path) -> None:
    views = tmp_path / "resources" / "views" / "orders"
    views.mkdir(parents=True)
    (views / "show.blade.php").write_text("<div>\n{!! $sort !!}\n</div>\n")

    project = load_project(tmp_path)
    rel = Path("resources/views/orders/show.blade.php")

    assert rel in project.blade
    assert rel not in project.files
    assert not project.blade[rel].has_errors


def test_blade_originals_back_the_snippets(tmp_path: Path) -> None:
    """Snippets must show Blade, not the PHP it was rewritten into."""
    views = tmp_path / "resources" / "views"
    views.mkdir(parents=True)
    (views / "show.blade.php").write_text("<div>\n  {!! $sort !!}\n</div>\n")

    project = load_project(tmp_path)
    rel = Path("resources/views/show.blade.php")

    assert project.blade_line(rel, 2) == "{!! $sort !!}"
    assert project.blade_line(rel, 999) == ""
