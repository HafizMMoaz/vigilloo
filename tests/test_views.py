from pathlib import Path

from tree_sitter import Node

from vigilloo.laravel.views import extract_view_bindings, template_path
from vigilloo.parser import find_all, parse_source


def _first_statement(php: str) -> tuple[Node, bytes]:
    parsed = parse_source(Path("t.php"), php.encode())
    stmt = find_all(parsed.tree.root_node, "return_statement")[0]
    return stmt, parsed.source


def _keys(binding) -> list[str]:
    return [key for key, _ in binding.variables]


def test_dotted_names_become_template_paths() -> None:
    assert template_path("orders.show") == Path("resources/views/orders/show.blade.php")
    assert template_path("welcome") == Path("resources/views/welcome.blade.php")


def test_unsafe_template_names_do_not_escape_the_view_root() -> None:
    """Names are read from analysed code, so they are untrusted input."""
    assert template_path("..") is None
    assert template_path(".hidden") is None
    assert template_path("") is None
    assert template_path("a/b") is None


def test_array_literal_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show', ['sort' => $sort]);")
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert bindings[0].template == "orders.show"
    assert _keys(bindings[0]) == ["sort"]
    assert bindings[0].compacted == ()


def test_compact_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show', compact('sort'));")
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert bindings[0].compacted == ("sort",)
    assert bindings[0].variables == ()


def test_fluent_with_binding() -> None:
    stmt, source = _first_statement("<?php return view('orders.show')->with('sort', $sort);")
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert bindings[0].template == "orders.show"
    assert _keys(bindings[0]) == ["sort"]


def test_double_quoted_names_resolve_too() -> None:
    """Single and double quoted literals are different node types."""
    stmt, source = _first_statement('<?php return view("orders.show", ["sort" => $sort]);')
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert bindings[0].template == "orders.show"


def test_eloquent_eager_loading_does_not_bind_a_template_variable() -> None:
    """with() is also Eloquent's eager-load method, and it is everywhere."""
    stmt, source = _first_statement(
        "<?php return view('orders.index', ['orders' => $q->with('items', $cb)->get()]);"
    )
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert _keys(bindings[0]) == ["orders"]


def test_every_view_call_in_a_statement_is_returned() -> None:
    stmt, source = _first_statement(
        "<?php return $flag ? view('a', ['x' => $x]) : view('b', ['y' => $y]);"
    )
    assert {b.template for b in extract_view_bindings(stmt, source)} == {"a", "b"}


def test_computed_template_name_is_returned_as_an_unresolved_binding() -> None:
    """view($name) cannot be resolved without guessing, but the call itself
    must not vanish - the caller needs it to record the coverage gap."""
    stmt, source = _first_statement("<?php return view($name, ['sort' => $sort]);")
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert bindings[0].template is None
    assert _keys(bindings[0]) == ["sort"]


def test_computed_template_name_with_compact_is_unresolved_but_not_dropped() -> None:
    stmt, source = _first_statement("<?php return view($name, compact('sort'));")
    bindings = extract_view_bindings(stmt, source)

    assert len(bindings) == 1
    assert bindings[0].template is None
    assert bindings[0].compacted == ("sort",)


def test_statement_without_a_view_call_binds_nothing() -> None:
    stmt, source = _first_statement("<?php return $this->orders->search($sort);")
    assert extract_view_bindings(stmt, source) == []
