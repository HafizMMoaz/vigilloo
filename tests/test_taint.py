from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.taint import find_taint_paths

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_finds_the_interprocedural_path_to_the_sink() -> None:
    paths = find_taint_paths(load_project(FIXTURE))
    assert len(paths) == 1

    roles = [step.role for step in paths[0]]
    assert roles == ["entry", "source", "propagator", "sink"]

    entry, source, propagator, sink = paths[0]
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
