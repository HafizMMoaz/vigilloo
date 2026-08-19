"""The format-neutral report, built once and rendered many times.

Every format renders this document rather than walking the `Finding` list
itself. Two formats each doing their own walk would eventually disagree about
what a scan found, and the one a developer reads is not the one CI gates on.

Sorting happens here, once, for the same reason: `scan_project` returns
findings in rule-dispatch order, which is an implementation detail. Invariant 8
requires byte-identical output for identical input, so the order every format
sees has to come from the finding's own content, never from the order the
engine happened to produce it in.
"""

from dataclasses import dataclass

from ..models import Coverage, Finding

# Bumped when a consumer reading the previous version would misread the new
# one: a removed key, a renamed key, or a changed type. Adding a key is not a
# break and does not bump it.
SCHEMA_VERSION = "1.0"

# Severity is an ordered scale, and sorted() on the string is alphabetical:
# "critical" would sort under "high" and "info" above "low". The report exists
# to put the worst finding first, so the rank is explicit.
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_UNKNOWN_SEVERITY_RANK = len(SEVERITY_ORDER)


def _sort_key(finding: Finding) -> tuple[int, str, str, int, int, str]:
    """docs/16-reporting: severity, rule ID, path, line.

    Two further components follow the four the spec names. Column and
    fingerprint break ties between findings that agree on all four, which
    happens when one line holds two sinks. Without them `sorted` would preserve
    input order for the tie, and input order is exactly what this key exists to
    stop mattering.
    """
    return (
        SEVERITY_ORDER.get(finding.severity, _UNKNOWN_SEVERITY_RANK),
        finding.rule_id,
        finding.span.file.as_posix(),
        finding.span.start_line,
        finding.span.start_col,
        finding.fingerprint,
    )


@dataclass(frozen=True)
class ReportMetadata:
    """What produced this report, and nothing about when.

    Invariant 8 forbids a timestamp or a duration here. Both change between two
    scans of unchanged code, which would make every report diff non-empty and
    make Task 9's precision measurement unreadable. Timing belongs to the
    terminal output and the store's scan row, neither of which is diffed.
    """

    engine_version: str
    ruleset_hash: str
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class ReportDocument:
    """One scan, sorted, ready for any format."""

    metadata: ReportMetadata
    coverage: Coverage
    findings: tuple[Finding, ...]

    @property
    def severity_counts(self) -> dict[str, int]:
        """Findings per severity, worst first, omitting severities with none.

        An absent severity and a severity with a zero count are the same fact.
        Emitting both shapes would let a consumer write a check that passes on
        one scan and fails on the next without the code having changed.
        """
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return dict(
            sorted(
                counts.items(),
                key=lambda item: SEVERITY_ORDER.get(item[0], _UNKNOWN_SEVERITY_RANK),
            )
        )


def build_document(
    findings: list[Finding],
    coverage: Coverage,
    engine_version: str,
    ruleset_hash: str,
) -> ReportDocument:
    """Assemble the document. Pure, and the only place findings are ordered."""
    return ReportDocument(
        metadata=ReportMetadata(engine_version=engine_version, ruleset_hash=ruleset_hash),
        coverage=coverage,
        findings=tuple(sorted(findings, key=_sort_key)),
    )
