from dataclasses import dataclass, field
from enum import Enum, auto

from tree_sitter import Node


class EdgeType(Enum):
    UNCONDITIONAL = auto()
    TRUE = auto()
    FALSE = auto()
    EXCEPTION = auto()


@dataclass
class Edge:
    target: "BasicBlock"
    edge_type: EdgeType = EdgeType.UNCONDITIONAL


@dataclass
class BasicBlock:
    id: int
    statements: list[Node] = field(default_factory=list)
    successors: list[Edge] = field(default_factory=list)
    predecessors: list["BasicBlock"] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BasicBlock):
            return NotImplemented
        return self.id == other.id

    def add_successor(
        self, target: "BasicBlock", edge_type: EdgeType = EdgeType.UNCONDITIONAL
    ) -> None:
        self.successors.append(Edge(target, edge_type))
        target.predecessors.append(self)


@dataclass
class CFG:
    entry: BasicBlock
    exit: BasicBlock
    blocks: list[BasicBlock]


class CFGBuilder:
    def __init__(self):
        self._block_id = 0
        self.blocks: list[BasicBlock] = []
        self.entry = self._new_block()
        self.exit = self._new_block()
        self.current_block = self.entry

        # Stacks for break/continue
        self.break_targets: list[BasicBlock] = []
        self.continue_targets: list[BasicBlock] = []

    def _new_block(self) -> BasicBlock:
        block = BasicBlock(id=self._block_id)
        self._block_id += 1
        self.blocks.append(block)
        return block

    def build(self, node: Node) -> CFG:
        if node.type in ("compound_statement", "program"):
            self._walk_compound(node)
        else:
            self._walk_statement(node)

        if self.current_block is not None:
            self.current_block.add_successor(self.exit)

        return CFG(entry=self.entry, exit=self.exit, blocks=self.blocks)

    def _walk_compound(self, node: Node) -> None:
        for child in node.children:
            if not child.is_named:
                continue
            self._walk_statement(child)
            if self.current_block is None:
                # unreachable code
                break

    def _walk_statement(self, node: Node) -> None:
        if self.current_block is None:
            return

        if node.type in ("compound_statement", "program"):
            self._walk_compound(node)
        elif node.type == "if_statement":
            self._walk_if(node)
        elif node.type in ("while_statement", "for_statement", "foreach_statement"):
            self._walk_loop(node)
        elif node.type == "do_statement":
            self._walk_do_while(node)
        elif node.type == "switch_statement":
            self._walk_switch(node)
        elif node.type == "match_expression":
            self._walk_match(node)
        elif node.type == "try_statement":
            self._walk_try(node)
        elif node.type in ("return_statement", "throw_expression", "exit_intrinsic"):
            self.current_block.statements.append(node)
            self.current_block.add_successor(self.exit)
            self.current_block = None
        elif node.type == "break_statement":
            self.current_block.statements.append(node)
            if self.break_targets:
                self.current_block.add_successor(self.break_targets[-1])
            self.current_block = None
        elif node.type == "continue_statement":
            self.current_block.statements.append(node)
            if self.continue_targets:
                self.current_block.add_successor(self.continue_targets[-1])
            self.current_block = None
        else:
            self.current_block.statements.append(node)

    def _walk_if(self, node: Node) -> None:
        self.current_block.statements.append(node)

        cond_block = self.current_block

        true_block = self._new_block()
        false_block = self._new_block()
        merge_block = self._new_block()

        cond_block.add_successor(true_block, EdgeType.TRUE)
        cond_block.add_successor(false_block, EdgeType.FALSE)

        self.current_block = true_block
        body = node.child_by_field_name("body")
        if body:
            self._walk_statement(body)
        if self.current_block:
            self.current_block.add_successor(merge_block)

        self.current_block = false_block
        alt = node.child_by_field_name("alternative")
        if alt:
            self._walk_statement(alt)
        if self.current_block:
            self.current_block.add_successor(merge_block)

        self.current_block = merge_block

    def _walk_loop(self, node: Node) -> None:
        self.current_block.statements.append(node)

        cond_block = self.current_block
        body_block = self._new_block()
        exit_block = self._new_block()

        cond_block.add_successor(body_block, EdgeType.TRUE)
        cond_block.add_successor(exit_block, EdgeType.FALSE)

        self.break_targets.append(exit_block)
        self.continue_targets.append(cond_block)

        self.current_block = body_block
        body = node.child_by_field_name("body")
        if body:
            self._walk_statement(body)
        if self.current_block:
            self.current_block.add_successor(cond_block)

        self.break_targets.pop()
        self.continue_targets.pop()

        self.current_block = exit_block

    def _walk_do_while(self, node: Node) -> None:
        self.current_block.statements.append(node)

        body_block = self._new_block()
        cond_block = self._new_block()
        exit_block = self._new_block()

        self.current_block.add_successor(body_block)

        self.break_targets.append(exit_block)
        self.continue_targets.append(cond_block)

        self.current_block = body_block
        body = node.child_by_field_name("body")
        if body:
            self._walk_statement(body)
        if self.current_block:
            self.current_block.add_successor(cond_block)

        cond_block.add_successor(body_block, EdgeType.TRUE)
        cond_block.add_successor(exit_block, EdgeType.FALSE)

        self.break_targets.pop()
        self.continue_targets.pop()

        self.current_block = exit_block

    def _walk_switch(self, node: Node) -> None:
        self.current_block.statements.append(node)

        cond_block = self.current_block
        exit_block = self._new_block()
        self.break_targets.append(exit_block)

        body = node.child_by_field_name("body")
        if body:
            cases = [c for c in body.children if c.type in ("case_statement", "default_statement")]

            case_blocks = [self._new_block() for _ in cases]

            for i, _ in enumerate(cases):
                cond_block.add_successor(case_blocks[i], EdgeType.TRUE)
                if i + 1 < len(case_blocks):
                    cond_block.add_successor(case_blocks[i + 1], EdgeType.FALSE)
                    cond_block = case_blocks[i]
                else:
                    cond_block.add_successor(exit_block, EdgeType.FALSE)

            for i, case_node in enumerate(cases):
                self.current_block = case_blocks[i]
                for child in case_node.children:
                    if child.is_named and child.type not in (
                        "expression",
                        "default_statement",
                        "case_statement",
                    ):
                        self._walk_statement(child)
                if self.current_block:
                    if i + 1 < len(case_blocks):
                        self.current_block.add_successor(case_blocks[i + 1])
                    else:
                        self.current_block.add_successor(exit_block)

        self.break_targets.pop()
        self.current_block = exit_block

    def _walk_match(self, node: Node) -> None:
        self.current_block.statements.append(node)
        # Match expressions aren't complex statement sequences, but they can be evaluated
        pass

    def _walk_try(self, node: Node) -> None:
        self.current_block.statements.append(node)

        body_block = self._new_block()
        exit_block = self._new_block()

        self.current_block.add_successor(body_block)
        self.current_block = body_block
        body = node.child_by_field_name("body")
        if body:
            self._walk_statement(body)
        if self.current_block:
            self.current_block.add_successor(exit_block)

        self.current_block = exit_block


def build_cfg(node: Node) -> CFG:
    builder = CFGBuilder()
    return builder.build(node)
