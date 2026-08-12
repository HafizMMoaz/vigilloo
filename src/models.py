"""Core data models shared by every subsystem.

All models are frozen, except WalkStats: a plain mutable counter, not a
finding-shaped record.
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class TaintKind(StrEnum):
    """A category of danger a tainted value carries.

    docs/06-taint-analysis tables eleven kinds. Only those with both sinks and
    sanitizers wired are declared here: marking a source `shell`-tainted when no
    sink can consume it and no sanitizer can clear it would claim reasoning the
    engine cannot do. Each remaining kind arrives with its sinks.

    Exception: `code` has sinks but no sanitizers. Untrusted data must never reach
    eval/unserialize at all; there is no sanitizer that makes it safe, so none is
    registered and none will ever be accepted in review.

    ponytail: js, path, url, ldap, xpath, header and log land with their own
    sink tables - see docs/06-taint-analysis.
    """

    SQL = "sql"
    HTML = "html"
    SHELL = "shell"
    PATH = "path"
    URL = "url"
    JS = "js"
    HEADER = "header"

    # Reaches eval(), unserialize(), create_function(), dynamic include/require.
    # Nothing clears this kind: there is no sanitizer that makes untrusted input
    # safe to pass to these sinks. Invariant: no SANITIZERS entry for CODE.
    CODE = "code"

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
    confidence: float = 1.0


@dataclass(frozen=True)
class EntryPoint:
    """A framework-invoked entry point (e.g., job, command, listener)."""

    fqn: str
    kind: str
    span: Span


@dataclass(frozen=True)
class NodeRow:
    """One graph node, ready to store.

    `id` is content-derived and comes from `vigilloo.ids.node_id` - invariant 3, and the
    reason `store.insert_nodes` can treat a repeat insert as a no-op instead of a conflict.
    Every span column is optional: a node that stands for a whole file or a route
    registration has no meaningful column offsets, and a zero would claim one it does not
    have.

    Lives here rather than in the store because the graph layer builds these and the store
    layer writes them, and the store already imports the graph. Nothing on it is a storage
    detail - it is the node model from docs/04-knowledge-graph in Python.
    """

    id: str
    kind: str
    name: str | None = None
    fqn: str | None = None
    file_id: int | None = None
    start_line: int | None = None
    start_col: int | None = None
    end_line: int | None = None
    end_col: int | None = None
    start_byte: int | None = None
    end_byte: int | None = None
    attrs: Mapping[str, object] | None = None


@dataclass(frozen=True)
class EdgeRow:
    """One graph edge, ready to store.

    `confidence` is not decoration (docs/04-knowledge-graph): a taint path carries the
    minimum confidence of its edges, and that value drives severity. It defaults to 1.0
    because a statically resolved edge is certain; anything resolved through a facade map or
    a variable callable must say so here and in `resolution`.
    """

    src_id: str
    dst_id: str
    kind: str
    confidence: float = 1.0
    resolution: str | None = None
    attrs: Mapping[str, object] | None = None


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
    confidence: float = 1.0


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
        """Exact identity. Changes when the code moves.

        Each step contributes its file, line and snippet, not just its role and
        line. A line number alone is not unique across files: two routes to the
        same unauthorized action declared at the same line of routes/web.php and
        routes/admin.php differ in URI and fingerprint and would otherwise
        collide here, and anything keyed on `id` - the store's primary key
        included - would silently drop one of them.
        """
        parts = [self.rule_id, str(self.span.file), str(self.span.start_line)]
        parts += [
            f"{s.role}:{s.span.file}:{s.span.start_line}:{s.snippet.strip()}"
            for s in self.evidence_path
        ]
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
    """A running count of the name resolutions the analysis attempted.

    `unresolved` counts the ones it had to give up on, `resolved` the ones it
    followed. Both are needed: a rate without its denominator can only be
    estimated, and invariant 4 says coverage is measured and reported.

    An attempt is counted where the walk had to turn a name in the source into
    something it could follow - a route registration into a route, a route into
    a controller action, a method call into a callee, a view() call into a
    template. Attempts are only counted where the answer would have changed what
    the analysis saw, so a benign unresolvable receiver carrying no taint is
    neither a success nor a failure: counting those would report gaps on correct
    code and train people to ignore the number.

    Not frozen: every other model here is an immutable record of something
    that happened, this is a counter incremented in place while the walk
    runs. Shared by vigilloo.taint and vigilloo.laravel.routes, both of which
    already depend on this module, so it lives here rather than in either of
    them to avoid an import cycle.
    """

    resolved: int = 0
    unresolved: int = 0


def _rate(succeeded: int, attempted: int) -> float:
    """The share of attempts that succeeded, as a fraction of 1.0.

    Zero attempts is 1.0, decided rather than stumbled into. The rate answers
    "of what this scan tried to read, how much did it understand", and nothing
    was missed when nothing was attempted; 0.0 would report a project with no
    PHP files as total blindness, and a CI gate (docs/22-testing, section
    "Metrics gated in CI") would then fail on an empty diff. The counts are
    reported next to every rate precisely so a vacuous 100% cannot be mistaken
    for a scanned codebase.
    """
    if attempted == 0:
        return 1.0
    return succeeded / attempted


@dataclass(frozen=True, order=True)
class ParseFailure:
    """One syntax error, attributed to the smallest named construct around it.

    A file path alone says a scan went blind somewhere in three hundred lines.
    That is enough to make the parse rate fall, which invariant 4 requires, and
    not enough to act on: the reader still has to find the break themselves, and
    a CI gate that fires names a filename rather than a cause. The construct is
    the actionable half of the same fact.

    `kind` is "file" and `name` empty when the error is at the top level and no
    named construct encloses it. That pairing is deliberately not fudged into a
    guess: an invented name would point somewhere that does not exist, which is
    worse than the file the reader already had.

    Ordered, so a report over these is stable however the tree was walked
    (invariant 8).
    """

    file: Path
    kind: str
    name: str

    @property
    def label(self) -> str:
        """One line naming what failed, for a human reading a report."""
        if not self.name:
            return f"{self.file} (top level)"
        return f"{self.kind} {self.name} ({self.file})"


@dataclass(frozen=True)
class Coverage:
    """What one scan managed to look at, in counts and the two rates over them.

    Invariant 4: coverage is reported, never hidden. A clean result over a
    codebase 40% of which failed to parse is a lie, and the only defence against
    telling it is measuring the fraction and printing it whether or not it is
    flattering.

    Counts are what was observed; the rates are derived, never stored, so the
    two can never disagree.

    `parse_failures` is detail hung off the same record, never an input to it:
    the rates are computed from the counts above and adding per-construct detail
    must not be able to move a number that docs/22-testing gates in CI. Several
    failures can share one file - one file, one unit of the parse rate - and a
    file can be counted in `files_with_errors` with no failure listed beside it,
    which is what a caller that did not collect the detail looks like.
    """

    files_discovered: int
    files_unreadable: int
    files_with_errors: int
    calls_resolved: int
    calls_unresolved: int
    parse_failures: tuple[ParseFailure, ...] = ()

    @property
    def files_parsed(self) -> int:
        """Files read and parsed with no syntax error anywhere in them."""
        return self.files_discovered - self.files_unreadable - self.files_with_errors

    @property
    def parse_success_rate(self) -> float:
        """Cleanly parsed files over every file discovered under the root.

        A file that could not be read counts against the rate exactly like one
        that would not parse: both are source the scan did not analyse, and the
        reason is of no comfort to the reader of the report.
        """
        return _rate(self.files_parsed, self.files_discovered)

    @property
    def calls_attempted(self) -> int:
        return self.calls_resolved + self.calls_unresolved

    @property
    def call_resolution_rate(self) -> float:
        """Followed resolutions over attempted ones.

        docs/22-testing calls this the leading indicator: unresolved calls are
        where false negatives hide, so it moves before missed findings do.
        """
        return _rate(self.calls_resolved, self.calls_attempted)
