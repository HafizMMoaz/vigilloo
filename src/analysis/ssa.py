from dataclasses import dataclass

from tree_sitter import Node

from .cfg import CFG


@dataclass(frozen=True)
class VariableVersion:
    name: str
    version: int


@dataclass(frozen=True)
class PhiNode:
    name: str
    # The whole union is the forward reference, not just the recursive half. Quoting only
    # `PhiNode` leaves `VariableVersion | str` to be evaluated, which is a TypeError on any
    # Python that evaluates annotations eagerly - every version this package supports except
    # 3.14, where PEP 649 made them lazy and hid this for as long as nobody ran 3.13.
    sources: frozenset["VariableVersion | PhiNode"]


SSAValue = VariableVersion | PhiNode


class SSABuilder:
    """Builds an SSA form over a CFG, assigning a VariableVersion to each variable.

    This performs a simple intraprocedural reaching definitions analysis.
    """

    def __init__(self, cfg: CFG, source: bytes) -> None:
        self.cfg = cfg
        self.source = source
        self._next_version: dict[str, int] = {}

        # State per block
        self.block_in: dict[int, dict[str, SSAValue]] = {}
        self.block_out: dict[int, dict[str, SSAValue]] = {}

        # Maps AST node id (Node.id) to the SSAValue read or written at that node
        self.reads: dict[int, SSAValue] = {}
        self.writes: dict[int, SSAValue] = {}

    def _new_version(self, name: str) -> VariableVersion:
        ver = self._next_version.get(name, 1)
        self._next_version[name] = ver + 1
        return VariableVersion(name, ver)

    def build(self) -> None:
        for block in self.cfg.blocks:
            self.block_in[block.id] = {}
            self.block_out[block.id] = {}

        worklist = list(self.cfg.blocks)
        while worklist:
            block = worklist.pop(0)

            # Compute IN
            new_in: dict[str, SSAValue] = {}
            if block.predecessors:
                incoming_vars: dict[str, set[SSAValue]] = {}
                for pred in block.predecessors:
                    for name, val in self.block_out[pred.id].items():
                        if name not in incoming_vars:
                            incoming_vars[name] = set()
                        incoming_vars[name].add(val)

                for name, vals in incoming_vars.items():
                    if len(vals) == 1:
                        new_in[name] = next(iter(vals))
                    else:
                        new_in[name] = PhiNode(name, frozenset(vals))

            self.block_in[block.id] = new_in

            current_state = dict(new_in)

            # Pass over block statements
            for stmt in block.statements:
                self._walk_node(stmt, current_state)

            if current_state != self.block_out[block.id]:
                self.block_out[block.id] = current_state
                for succ_edge in block.successors:
                    if succ_edge.target not in worklist:
                        worklist.append(succ_edge.target)

    def _walk_node(self, node: Node, state: dict[str, SSAValue]) -> None:
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if right:
                self._walk_node(right, state)
            if left:
                # Handle assignment
                self._handle_assignment(left, state)
        elif node.type == "foreach_statement":
            # foreach ($arr as $k => $v) or foreach ($arr as $v)
            # $arr is read
            array_node = node.child_by_field_name("array")
            if array_node:
                self._walk_node(array_node, state)

            value_node = node.child_by_field_name("value")
            if value_node:
                self._handle_assignment(value_node, state)

            key_node = node.child_by_field_name("key")
            if key_node:
                self._handle_assignment(key_node, state)

            body_node = node.child_by_field_name("body")
            if body_node:
                self._walk_node(body_node, state)

        elif node.type == "list_literal":  # list($x, $y) = ...
            for child in node.children:
                if child.is_named:
                    self._handle_assignment(child, state)

        elif node.type == "variable_name":
            # Variable read
            name = self._var_name(node)
            if name in state:
                self.reads[node.id] = state[name]

        else:
            for child in node.children:
                if child.is_named:
                    self._walk_node(child, state)

    def _handle_assignment(self, node: Node, state: dict[str, SSAValue]) -> None:
        if node.type == "variable_name":
            name = self._var_name(node)
            if node.id in self.writes:
                ver = self.writes[node.id]
            else:
                ver = self._new_version(name)
                self.writes[node.id] = ver
            state[name] = ver
        elif node.type == "subscript_expression":
            # Assignment to array element: reads the base array,
            # writes a new version of the base array
            base = node.children[0] if node.children else None
            if base and base.type == "variable_name":
                name = self._var_name(base)
                # First, it reads the old version
                if name in state:
                    self.reads[base.id] = state[name]
                # Then it writes a new version
                if base.id in self.writes:
                    ver = self.writes[base.id]
                else:
                    ver = self._new_version(name)
                    self.writes[base.id] = ver
                state[name] = ver
            else:
                self._walk_node(node, state)
        elif node.type == "list_literal" or node.type == "array_creation_expression":
            # destructuring
            for child in node.children:
                if child.is_named:
                    self._handle_assignment(child, state)
        else:
            # Maybe a property access $this->foo = 1
            # We treat the base object as being read,
            # but property sensitivity is beyond this simple SSA for now
            self._walk_node(node, state)

    def _var_name(self, node: Node) -> str:
        # Extracts name without $
        text = node.text
        if text is None:
            return ""
        text_str = text.decode("utf-8") if isinstance(text, bytes) else text
        return text_str.lstrip("$")
