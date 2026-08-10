from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.models import ALL_KINDS
from vigilloo.parser import find_all
from vigilloo.taint import expr_kinds


def test_expr(tmp_path: Path):
    path = tmp_path / "app/Jobs/ProcessOrder.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("""<?php
    $x = $this->orderId;
    """)
    project = load_project(tmp_path)
    parsed = list(project.files.values())[0]

    expr = find_all(parsed.tree.root_node, "member_access_expression")[0]
    kinds = expr_kinds(expr, parsed.source, {"this": ALL_KINDS}, frozenset(), lambda x: None)
    print("Kinds:", kinds)
