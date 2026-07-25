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
