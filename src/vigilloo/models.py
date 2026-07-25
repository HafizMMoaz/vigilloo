"""Core data models shared by every subsystem.

All models are frozen. A rule must never mutate a finding it did not create.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Span:
    """A byte range in a source file, as 1-indexed lines and 0-indexed columns."""

    file: Path
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __str__(self) -> str:
        return f"{self.file}:{self.start_line}"


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

    role is one of: source, propagator, sanitizer, sink, entry.
    """

    role: str
    span: Span
    snippet: str
    note: str = ""


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
    confidence: float = 1.0

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
        """Location-independent identity, so baselines survive a reformat."""
        parts = [self.rule_id, str(self.span.file)]
        parts += [f"{s.role}:{s.snippet.strip()}" for s in self.evidence_path]
        return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]
