from pathlib import Path
from vigilloo.graph import parse_php

tmp_path = Path("scratch/tmp")
config_dir = tmp_path / "config"
parsed = parse_php(config_dir / "app.php")
def print_fields(node):
    if node.type == "class_constant_access_expression":
        cursor = node.walk()
        if cursor.goto_first_child():
            while True:
                print(f"Child {cursor.node.type} field_name={cursor.field_name}")
                if not cursor.goto_next_sibling():
                    break
    for child in node.children:
        print_fields(child)
print_fields(parsed.tree.root_node)
