"""The canonical, lossless serialisation. Everything else is derived from it.

This is the format Task 9's precision harness diffs, so invariant 8 is not an
aspiration here: two scans of unchanged code must produce the same bytes, on
any host. Three things make that true and each is easy to break by accident:

* `sort_keys=True`, so a dict built in a different order serialises the same.
* `Path.as_posix()`, so a Windows run does not emit backslashes.
* No timestamp and no duration anywhere in the body. `ReportMetadata` refuses
  to carry them; the terminal output and the store's scan row keep them.
"""

import json

from ..models import Coverage, Finding, PathStep, Span
from .document import ReportDocument

# Rates are derived floats. Two runs on one host agree exactly, but the corpus
# harness compares runs across hosts and CI images, so they are rounded to a
# fixed precision rather than trusted to repr identically. The counts either
# side of them are integers and are the exact values the rate came from, so
# nothing is lost by rounding the convenience value.
_RATE_PRECISION = 6


def _span(span: Span) -> dict[str, object]:
    return {
        "file": span.file.as_posix(),
        "start_line": span.start_line,
        "start_col": span.start_col,
        "end_line": span.end_line,
        "end_col": span.end_col,
    }


def _step(step: PathStep) -> dict[str, object]:
    return {
        "role": step.role,
        "location": _span(step.span),
        "snippet": step.snippet,
        "note": step.note,
        "rule_id": step.rule_id,
        "confidence": step.confidence,
    }


def _finding(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "cwe": list(finding.cwe),
        "location": _span(finding.span),
        "evidence_path": [_step(step) for step in finding.evidence_path],
        "alternative_paths": [[_step(step) for step in path] for path in finding.alternative_paths],
        "remediation": finding.remediation,
        "needs_review": finding.needs_review,
    }


def _coverage(coverage: Coverage) -> dict[str, object]:
    """Counts and the rates derived from them.

    The rates are emitted alongside the counts rather than left to the
    consumer, because invariant 4 is about what a reader sees without effort. A
    consumer that has to divide two numbers to learn a scan was 60% blind is a
    consumer that will not.
    """
    return {
        "files_discovered": coverage.files_discovered,
        "files_unreadable": coverage.files_unreadable,
        "files_with_errors": coverage.files_with_errors,
        "files_parsed": coverage.files_parsed,
        "parse_success_rate": round(coverage.parse_success_rate, _RATE_PRECISION),
        "calls_resolved": coverage.calls_resolved,
        "calls_unresolved": coverage.calls_unresolved,
        "calls_attempted": coverage.calls_attempted,
        "call_resolution_rate": round(coverage.call_resolution_rate, _RATE_PRECISION),
        "parse_failures": [
            {"file": failure.file.as_posix(), "kind": failure.kind, "name": failure.name}
            for failure in coverage.parse_failures
        ],
    }


def render_json(document: ReportDocument) -> str:
    """Serialise one scan. Returns the text; printing is the caller's job.

    Returning a string rather than printing is what lets `--format json` write
    to stdout while every coverage caveat goes to stderr, and it keeps this
    module under the T20 lint rule that would otherwise not protect it.
    """
    payload = {
        "schema_version": document.metadata.schema_version,
        "tool": {
            "name": "vigilloo",
            "version": document.metadata.engine_version,
            "ruleset_hash": document.metadata.ruleset_hash,
        },
        "summary": {
            "total": len(document.findings),
            "by_severity": document.severity_counts,
        },
        "coverage": _coverage(document.coverage),
        "findings": [_finding(finding) for finding in document.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
