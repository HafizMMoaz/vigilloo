from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.parser import find_all, node_text

tmp_path = Path("/tmp/vigilloo_test_container")
project = load_project(tmp_path)
for path, parsed in project.files.items():
    if "PaymentController.php" in str(path):
        source = parsed.source
        for node in find_all(parsed.tree.root_node, "function_call_expression"):
            name_node = node.child_by_field_name("function")
            print("Name field 'function':", node_text(name_node, source))
