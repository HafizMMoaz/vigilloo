from vigilloo.analysis.cfg import build_cfg, EdgeType
from tree_sitter import Parser, Language
import tree_sitter_php


# Note: this might need adjustment depending on how parser is initialized in the project
def parse_snippet(code: str):
    LANGUAGE = Language(tree_sitter_php.language_php())
    parser = Parser(LANGUAGE)
    # wrap in php tags for tree-sitter
    tree = parser.parse(f"<?php\n{code}".encode("utf-8"))
    # returns the compound_statement of a method body roughly
    # for simplicity, we assume the code is just statements
    return tree.root_node


def test_cfg_straight_line():
    code = """
    $a = 1;
    $b = 2;
    """
    root = parse_snippet(code)
    cfg = build_cfg(root)
    # Entry and Exit
    assert len(cfg.blocks) == 2
    assert len(cfg.entry.successors) == 1
    assert cfg.entry.successors[0].target == cfg.exit


def test_cfg_if_statement():
    code = """
    if ($a) {
        $b = 1;
    } else {
        $c = 2;
    }
    """
    root = parse_snippet(code)
    cfg = build_cfg(root)
    # entry -> cond -> true/false -> merge -> exit
    assert len(cfg.blocks) == 5
    assert len(cfg.entry.successors) == 2


def test_cfg_loops():
    code = """
    while ($a) {
        $b = 1;
        if ($b) {
            break;
        } else {
            continue;
        }
    }
    """
    root = parse_snippet(code)
    cfg = build_cfg(root)
    assert len(cfg.blocks) == 7


def test_cfg_switch():
    code = """
    switch ($a) {
        case 1:
            $b = 1;
            break;
        case 2:
            $b = 2;
        default:
            $b = 3;
    }
    """
    root = parse_snippet(code)
    cfg = build_cfg(root)
    assert len(cfg.blocks) == 6


def test_cfg_try():
    code = """
    try {
        $a = 1;
    } catch (Exception $e) {
        $b = 2;
    } finally {
        $c = 3;
    }
    """
    root = parse_snippet(code)
    cfg = build_cfg(root)
    assert len(cfg.blocks) == 4
