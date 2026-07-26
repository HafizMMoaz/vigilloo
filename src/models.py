"""Core data models shared by every subsystem.

All models are frozen, except WalkStats: a plain mutable counter, not a
finding-shaped record.
"""

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class TaintKind(StrEnum):
    """A category of danger a tainted value carries.

    docs/06-taint-analysis tables eleven kinds. Only those with both sinks and
    sanitizers wired are declared here: marking a source `code`-tainted when no
    sink can consume it and no sanitizer can clear it would claim reasoning the
    engine cannot do. Each remaining kind arrives with its sinks.

    ponytail: three kinds. js, shell, path, url, code, ldap, xpath, header and
    log land with their own sink tables - see docs/06-taint-analysis.
    """

    SQL = "sql"
    HTML = "html"

    # Not an injection kind like the others: it marks a value whose *keys* the
    # attacker chose, which is what makes an Eloquent array write dangerous.
    # $request->only([...]) and ->validated() are XSS- and SQL-dangerous while
    # being perfectly safe to mass-assign, and no boolean over the other kinds
    # can express that difference.
    MASS_ASSIGN = "mass_assign"


ALL_KINDS: frozenset[TaintKind] = frozenset(TaintKind)


@dataclass(frozen=True)
class Span:
    """A byte range in a source file, as 1-indexed lines and 0-indexed columns."""

    file: Path
    start_line: int
    start_col: int
    end_line: int
    end_col: int


@dataclass(frozen=True)
class Symbol:
    """A named declaration: class, method or function."""

    fqn: str
    kind: str
    span: Span
    params: tuple[str, ...] = ()
    param_types: tuple[str | None, ...] = ()


@dataclass(frozen=True)
class Route:
    """An HTTP entry point mapped to a controller action."""

    uri: str
    verbs: tuple[str, ...]
    action_fqn: str
    middleware: tuple[str, ...]
    span: Span


@dataclass(frozen=True)
class PathStep:
    """One step in a finding's evidence path.

    role is one of: entry, source, propagator, sanitizer, model, sink for a
    taint path, and entry, binding, policy, gap for a structural one.

    rule_id is set on the final step and empty everywhere else. The analysis is
    the only layer that knows which rule it matched, and the security engine is
    the only layer that knows what rules are, so the walk names the rule and
    rules.py looks it up. Passing a Rule object here instead would put the
    security engine's vocabulary inside the graph layer, which the layering
    rule forbids.
    """

    role: str
    span: Span
    snippet: str
    note: str = ""
    rule_id: str = ""


@dataclass(frozen=True)
class Finding:
    """A security finding with a complete evidence path."""

    rule_id: str
    severity: str
    title: str
    cwe: tuple[str, ...]
    span: Span
    evidence_path: tuple[PathStep, ...]
    remediation: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_path:
            raise ValueError(
                f"finding {self.rule_id} has an empty evidence path; "
                "a finding without a path is a bug in Vigilloo"
            )

    @property
    def id(self) -> str:
        """Exact identity. Changes when the code moves."""
        parts = [self.rule_id, str(self.span.file), str(self.span.start_line)]
        parts += [f"{s.role}:{s.span.start_line}" for s in self.evidence_path]
        return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]

    @property
    def fingerprint(self) -> str:
        """Identity that survives line movement within a file.

        Hashes the rule, the file path and the evidence path snippets, but no
        line numbers, so a reformat that shifts code does not resurrect a
        suppressed finding. The file path is deliberately included: the same
        pattern in two files is two distinct findings, and collapsing them
        would silently drop one. A file rename therefore does reset the
        fingerprint, which is the accepted trade for that safety.
        """
        parts = [self.rule_id, str(self.span.file)]
        parts += [f"{s.role}:{s.snippet.strip()}" for s in self.evidence_path]
        return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


@dataclass
class WalkStats:
    """A running count of call sites the analysis had to give up on.

    Not frozen: every other model here is an immutable record of something
    that happened, this is a counter incremented in place while the walk
    runs. Shared by vigilloo.taint and vigilloo.laravel.routes, both of which
    already depend on this module, so it lives here rather than in either of
    them to avoid an import cycle.
    """

    unresolved: int = 0
