from dataclasses import dataclass, field

from .models import PathStep, TaintKind


@dataclass
class FunctionSummary:
    fqn: str
    paths_by_taint: dict[frozenset[tuple[str, frozenset[TaintKind]]], list[list[PathStep]]] = field(
        default_factory=dict
    )
    param_to_return: dict[int, frozenset[TaintKind]] = field(default_factory=dict)
    param_to_param: dict[int, set[int]] = field(default_factory=dict)
    param_to_property: dict[int, set[str]] = field(default_factory=dict)
    sanitizes: dict[int, frozenset[TaintKind]] = field(default_factory=dict)
    returns_tainted: frozenset[TaintKind] = frozenset()
