"""Print the Tree-sitter s-expression for a PHP file.

Usage: uv run python scripts/dump_ast.py <path-to-php-file>
"""

import sys
from pathlib import Path

import tree_sitter_php
from tree_sitter import Language, Parser


def main() -> None:
    language = Language(tree_sitter_php.language_php())
    parser = Parser(language)
    source = Path(sys.argv[1]).read_bytes()
    tree = parser.parse(source)
    print(tree.root_node)


if __name__ == "__main__":
    main()
