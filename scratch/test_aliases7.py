from pathlib import Path
from vigilloo.graph import parse_php, node_text, find_all
tmp_path = Path("scratch/tmp6")
parsed = parse_php(tmp_path / "config" / "app.php")
aliases = {}
for element in find_all(parsed.tree.root_node, "array_element_initializer"):
    key = element.child_by_field_name("key")
    if not key or key.type != "string":
        continue
    key_text = ""
    for child in key.named_children:
        if child.type == "string_content":
            key_text += node_text(child, parsed.source)
    print(f"Found key_text: {key_text}")
    if key_text == "aliases":
        value = element.child_by_field_name("value")
        print(f"Value type: {value.type if value else 'None'}")
        if not value or value.type != "array_creation_expression":
            continue
        for alias_el in find_all(value, "array_element_initializer"):
            alias_key = alias_el.child_by_field_name("key")
            alias_val = alias_el.child_by_field_name("value")
            if not alias_key or alias_key.type != "string" or not alias_val:
                continue
            alias_name = ""
            for child in alias_key.named_children:
                if child.type == "string_content":
                    alias_name += node_text(child, parsed.source)
            print(f"  Alias key: {alias_name}, val type: {alias_val.type}")
            if alias_val.type == "class_constant_access_expression":
                cls_node = alias_val.children[0]
                aliases[alias_name] = node_text(cls_node, parsed.source)
            elif alias_val.type == "string":
                val_text = ""
                for child in alias_val.named_children:
                    if child.type == "string_content":
                        val_text += node_text(child, parsed.source)
                aliases[alias_name] = val_text.replace("\\\\", "\\")
        break
print(aliases)
