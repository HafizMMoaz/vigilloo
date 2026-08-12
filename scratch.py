import tree_sitter_php
from tree_sitter import Language, Parser

from vigilloo.models import TaintKind
from vigilloo.taint import expr_kinds

PHP_LANGUAGE = Language(tree_sitter_php.language_php())
parser = Parser(PHP_LANGUAGE)
source = b"<?php Js::from($x); ?>"
tree = parser.parse(source)
node = tree.root_node.children[1].children[0]
print(expr_kinds(node, source, {"$x": frozenset({TaintKind.JS, TaintKind.HTML})}))
