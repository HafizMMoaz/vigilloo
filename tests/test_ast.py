from pathlib import Path
from vigilloo.parser import parse_source, find_all

def test_ast():
    parsed = parse_source(Path("test.php"), b"<?php env('DB_HOST');")
    tree = parsed.tree
    for call in find_all(tree.root_node, "function_call_expression"):
        print("function field:", call.child_by_field_name("function"))
    assert False
