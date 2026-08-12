import tree_sitter_php
from tree_sitter import Language, Parser, Node
from vigilloo.analysis.cfg import CFGBuilder
from vigilloo.analysis.ssa import SSABuilder, PhiNode, VariableVersion


def parse_snippet(code: str) -> tuple[Node, bytes]:
    LANGUAGE = Language(tree_sitter_php.language_php())
    parser = Parser(LANGUAGE)
    source = f"<?php\n{code}".encode()
    tree = parser.parse(source)
    return tree.root_node, source


def test_linear_reassignment():
    code = """
    $x = 1;
    $x = 2;
    """
    root, source = parse_snippet(code)

    cfg_builder = CFGBuilder()
    cfg = cfg_builder.build(root)

    ssa_builder = SSABuilder(cfg, source)
    ssa_builder.build()

    # Check that $x is assigned twice with different versions
    writes = list(ssa_builder.writes.values())
    assert len(writes) == 2
    assert writes[0].name == "x"
    assert writes[0].version == 1
    assert writes[1].name == "x"
    assert writes[1].version == 2


def test_branch_join_phi():
    code = """
    $x = 1;
    if ($cond) {
        $x = 2;
    } else {
        $x = 3;
    }
    $y = $x;
    """
    root, source = parse_snippet(code)

    cfg_builder = CFGBuilder()
    cfg = cfg_builder.build(root)

    ssa_builder = SSABuilder(cfg, source)
    ssa_builder.build()

    # Check that reading $x at the end returns a Phi node
    # Find the read of $x in `$y = $x;`
    reads = list(ssa_builder.reads.values())
    assert len(reads) >= 1
    # One of the reads is $cond, another is $x
    x_read = [r for r in reads if r.name == "x"][-1]

    assert isinstance(x_read, PhiNode)
    assert x_read.name == "x"
    assert len(x_read.sources) == 2
    versions = {s.version for s in x_read.sources}
    # It should merge version 2 (from if) and 3 (from else)
    assert versions == {2, 3}
