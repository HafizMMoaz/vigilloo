# tests/test_parser.py
from pathlib import Path

import pytest

from vigilloo.parser import error_constructs, find_all, node_text, parse_php, parse_source

FIXTURE = Path("tests/fixtures/laravel-minimal")
BROKEN = Path("tests/fixtures/laravel-unparseable")


def test_parses_controller_without_errors() -> None:
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    assert not parsed.has_errors
    assert parsed.tree.root_node.type == "program"


def test_finds_method_declarations() -> None:
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    methods = find_all(parsed.tree.root_node, "method_declaration")
    names = {
        node_text(m.child_by_field_name("name"), parsed.source)
        for m in methods
        if m.child_by_field_name("name") is not None
    }
    assert {"__construct", "search", "recent"} <= names


def test_broken_file_is_partial_not_fatal(tmp_path: Path) -> None:
    """A parse error degrades one file, it never aborts a scan."""
    broken = tmp_path / "broken.php"
    broken.write_text("<?php class { function (")
    parsed = parse_php(broken)
    assert parsed.has_errors


def test_a_broken_method_is_reported_as_the_method_not_the_file() -> None:
    """The acceptance case for TASK-031.

    The fixture's only syntax error is inside one method, and "this file did not
    parse" is a fact the reader cannot act on: it names three hundred lines. The
    construct is the actionable form of the same fact.
    """
    parsed = parse_php(BROKEN / "app/Http/Controllers/ReportController.php")

    failures = error_constructs(parsed)

    assert [(f.kind, f.name) for f in failures] == [("method", "ReportController::index")]


def test_one_broken_construct_is_reported_once() -> None:
    """Deduplication, over the fixture that actually produces two error nodes.

    Its method has both an unclosed parameter list and an unterminated call, so
    tree-sitter marks it twice. Reporting the same method twice would make the
    detail read like two separate problems.
    """
    parsed = parse_php(BROKEN / "app/Http/Controllers/ReportController.php")

    assert len(error_constructs(parsed)) == 1


def test_a_top_level_error_falls_back_to_the_file(tmp_path: Path) -> None:
    """The honest fallback. No construct encloses this, so none is claimed."""
    broken = tmp_path / "bootstrap.php"
    broken.write_text("<?php\n\n$total = ;\n")
    parsed = parse_php(broken)

    failures = error_constructs(parsed)

    assert [(f.kind, f.name) for f in failures] == [("file", "")]
    assert failures[0].label == f"{broken} (top level)"


def test_an_anonymous_construct_is_not_given_an_invented_name() -> None:
    """A closure has no name, so the enclosing function is reported instead.

    The alternative - reporting `function ` with an empty name - would point the
    reader at a construct they cannot search for, which is worse than the wider
    scope that at least exists.
    """
    parsed = parse_source(
        Path("app/helpers.php"),
        b"<?php\nfunction boot() {\n    $f = function () { $x = ; };\n}\n",
    )

    failures = error_constructs(parsed)

    assert [(f.kind, f.name) for f in failures] == [("function", "boot")]


def test_failures_are_sorted_rather_than_walk_ordered() -> None:
    """Invariant 8: the same file must render byte-identically every time.

    Two broken methods in one class come out in name order, not in whatever
    order the tree happened to be descended.
    """
    parsed = parse_source(
        Path("app/C.php"),
        b"<?php\nclass C\n{\n    public function zeta() { $a = ; }\n"
        b"    public function alpha() { $b = ; }\n}\n",
    )

    failures = error_constructs(parsed)

    assert [f.name for f in failures] == ["C::alpha", "C::zeta"]


def test_a_clean_file_is_answered_without_walking_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """The performance guarantee: a healthy project pays one boolean read.

    Every file in every clean codebase takes this path, so a tree walk here
    would be a walk over the whole project for a feature only broken files use.
    Asserted by making the walk itself fail rather than by timing it.
    """

    def explode(node: object) -> None:
        raise AssertionError("a clean file must not be walked for parse failures")

    monkeypatch.setattr("vigilloo.parser._error_nodes", explode)
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")

    assert not parsed.has_errors
    assert error_constructs(parsed) == ()
