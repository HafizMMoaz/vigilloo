from pathlib import Path

from vigilloo.graph import find_all, parse_php

tmp_path = Path("scratch/tmp6")
parsed = parse_php(tmp_path / "config" / "app.php")
for el in find_all(parsed.tree.root_node, "array_element_initializer"):
    cursor = el.walk()
    if cursor.goto_first_child():
        while True:
            print(f"Child {cursor.node.type} field_name={cursor.field_name}")
            if not cursor.goto_next_sibling():
                break
    break
