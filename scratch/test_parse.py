from pathlib import Path

from vigilloo.parser import find_all, node_text, parse_php


def test_parse():
    parsed = parse_php(Path("scratch/config_app_test.php"))
    for element in find_all(parsed.tree.root_node, "array_element_initializer"):
        key = element.child_by_field_name("key")
        if key and key.type == "string":
            key_text = ""
            for child in key.named_children:
                if child.type == "string_content":
                    key_text += node_text(child, parsed.source)
            if key_text == "aliases":
                value = element.child_by_field_name("value")
                if value and value.type == "array_creation_expression":
                    for alias_el in find_all(value, "array_element_initializer"):
                        alias_key = alias_el.child_by_field_name("key")
                        alias_val = alias_el.child_by_field_name("value")
                        if alias_key and alias_key.type == "string":
                            alias_name = ""
                            for child in alias_key.named_children:
                                if child.type == "string_content":
                                    alias_name += node_text(child, parsed.source)

                            if alias_val and alias_val.type == "class_constant_access_expression":
                                cls_node = alias_val.child_by_field_name("class")
                                if cls_node:
                                    cls = node_text(cls_node, parsed.source)
                                    print(f"Alias: {alias_name} -> {cls}")


test_parse()
