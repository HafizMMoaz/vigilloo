# tests/test_parser.py
from pathlib import Path

from vigilloo.parser import find_all, node_text, parse_php

FIXTURE = Path("tests/fixtures/laravel-minimal")


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


def test_broken_file_is_partial_not_fatal() -> None:
    """A parse error degrades one file, it never aborts a scan."""
    broken = Path("tests/fixtures/broken.php")
    broken.write_text("<?php class { function (")
    try:
        parsed = parse_php(broken)
        assert parsed.has_errors
    finally:
        broken.unlink()
