from pathlib import Path

from vigilloo.laravel.views import extract_view_binding, template_path
from vigilloo.parser import find_all, parse_source


def _first_statement(php: str):
    parsed = parse_source(Path("t.php"), php.encode())
    stmt = find_all(parsed.tree.root_node, "return_statement")[0]
    return stmt, parsed.source


def test_dotted_names_become_template_paths() -> None:
    assert template_path("orders.show") == Path("resources/views/orders/show.blade.php")
    assert template_path("welcome") == Path("resources/views/welcome.blade.php")


def test_array_literal_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show', ['sort' => $sort]);")
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.template == "orders.show"
    assert set(binding.variables) == {"sort"}
    assert binding.compacted == ()


def test_compact_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show', compact('sort'));")
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.compacted == ("sort",)
    assert binding.variables == {}


def test_fluent_with_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show')->with('sort', $sort);")
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.template == "orders.show"
    assert set(binding.variables) == {"sort"}


def test_double_quoted_names_resolve_too() -> None:
    """Single and double quoted literals are different node types in the grammar."""
    stmt, source = _first_statement('<?php return view("orders.show", ["sort" => $sort]);')
    binding = extract_view_binding(stmt, source)

    assert binding is not None
    assert binding.template == "orders.show"


def test_computed_template_name_is_unresolvable() -> None:
    """view($name) cannot be resolved without guessing, so it is not resolved."""
    stmt, source = _first_statement("<?php return view($name, ['sort' => $sort]);")
    assert extract_view_binding(stmt, source) is None


def test_statement_without_a_view_call_binds_nothing() -> None:
    stmt, source = _first_statement("<?php return $this->orders->search($sort);")
    assert extract_view_binding(stmt, source) is None
