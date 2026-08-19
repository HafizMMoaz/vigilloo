from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.models import ALL_KINDS
from vigilloo.parser import find_all
from vigilloo.taint import LocalState, expr_kinds


def test_expr(tmp_path: Path):
    """A property read on a variable already carrying every kind (`$this` bound to
    ALL_KINDS) is an unrecognised construct for expr_kinds - there is no per-property
    tracking - so it falls through to the union-over-children default and preserves
    the base variable's full taint rather than silently dropping it.
    """
    path = tmp_path / "app/Jobs/ProcessOrder.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("""<?php
    $x = $this->orderId;
    """)
    project = load_project(tmp_path)
    parsed = list(project.files.values())[0]

    expr = find_all(parsed.tree.root_node, "member_access_expression")[0]
    local = LocalState({"this": ALL_KINDS}, None)
    kinds = expr_kinds(expr, parsed.source, local, frozenset(), lambda x: None)
    assert kinds == ALL_KINDS
