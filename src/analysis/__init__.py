"""Analysis package: control-flow graph, SSA, and interprocedural taint engine."""

from .cfg import CFG, BasicBlock, CFGBuilder, Edge, EdgeType, build_cfg
from .ssa import PhiNode, SSABuilder, VariableVersion
from .taint import LocalState, WalkStats, expr_kinds, find_taint_paths

__all__ = [
    "CFG",
    "BasicBlock",
    "CFGBuilder",
    "Edge",
    "EdgeType",
    "LocalState",
    "PhiNode",
    "SSABuilder",
    "VariableVersion",
    "WalkStats",
    "build_cfg",
    "expr_kinds",
    "find_taint_paths",
]
