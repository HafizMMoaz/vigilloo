"""SARIF 2.1.0 reporter for CI systems and code scanning dashboards.

Complies with the OASIS SARIF 2.1.0 JSON schema
(https://json.schemastore.org/sarif-2.1.0.json).

Supports:
- Rule catalogue with help text, remediation, CWE tags, and GitHub security-severity scores.
- Code flows (codeFlows and threadFlows) mapping finding evidence paths step by step.
- Partial fingerprints (vigillooFingerprint) for cross-commit finding tracking.
- Invocation execution status and parse failure notifications for coverage transparency.
- Deterministic, byte-identical output across runs.
"""

import json
from typing import Any

from ..models import Finding, PathStep, Span
from ..rules import RULES_BY_ID
from .document import ReportDocument

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_INFORMATION_URI = "https://github.com/HafizMMoaz/vigilloo"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SEVERITY_TO_SECURITY_SCORE: dict[str, str] = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}


def _sarif_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity.lower(), "warning")


def _security_severity(severity: str) -> str:
    return _SEVERITY_TO_SECURITY_SCORE.get(severity.lower(), "5.0")


def _physical_location(span: Span, snippet_text: str = "") -> dict[str, Any]:
    loc: dict[str, Any] = {
        "artifactLocation": {
            "uri": span.file.as_posix(),
            "uriBaseId": "%SRCROOT%",
        },
        "region": {
            "startLine": span.start_line,
            "startColumn": span.start_col,
            "endLine": span.end_line,
            "endColumn": span.end_col,
        },
    }
    if snippet_text:
        loc["region"]["snippet"] = {"text": snippet_text}
    return loc


def _thread_flow_location(step: PathStep, order: int) -> dict[str, Any]:
    msg = f"[{step.role.upper()}] {step.note}" if step.note else f"[{step.role.upper()}]"
    importance = "essential" if step.role in ("source", "sink") else "important"
    return {
        "location": {
            "physicalLocation": _physical_location(step.span, snippet_text=step.snippet),
            "message": {"text": msg},
        },
        "importance": importance,
        "executionOrder": order,
    }


def _code_flows(finding: Finding) -> list[dict[str, Any]]:
    if not finding.evidence_path:
        return []
    locations = [
        _thread_flow_location(step, idx + 1) for idx, step in enumerate(finding.evidence_path)
    ]
    return [
        {
            "threadFlows": [
                {
                    "locations": locations,
                }
            ]
        }
    ]


def _build_rule_record(rule_id: str) -> dict[str, Any]:
    rule = RULES_BY_ID.get(rule_id)
    if rule is not None:
        title = rule.title
        severity = rule.severity
        remediation = rule.remediation
        cwe_list = list(rule.cwe)
        owasp_list = list(rule.owasp)
    else:
        title = rule_id
        severity = "medium"
        remediation = ""
        cwe_list = []
        owasp_list = []

    tags = sorted(list(set(["security", "laravel", *cwe_list, *owasp_list])))
    help_text = f"{title}\n\nRemediation:\n{remediation}" if remediation else title
    help_md = f"### {title}\n\n**Remediation:**\n{remediation}" if remediation else f"### {title}"

    return {
        "id": rule_id,
        "name": rule_id.replace(".", "_").replace("-", "_"),
        "shortDescription": {"text": title},
        "fullDescription": {"text": title},
        "help": {
            "text": help_text,
            "markdown": help_md,
        },
        "helpUri": TOOL_INFORMATION_URI,
        "defaultConfiguration": {
            "level": _sarif_level(severity),
        },
        "properties": {
            "precision": "high",
            "security-severity": _security_severity(severity),
            "tags": tags,
        },
    }


def _build_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    snippet = finding.evidence_path[-1].snippet if finding.evidence_path else ""
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.title},
        "locations": [
            {
                "physicalLocation": _physical_location(finding.span, snippet_text=snippet),
            }
        ],
        "partialFingerprints": {
            "vigillooFingerprint": finding.fingerprint,
        },
        "codeFlows": _code_flows(finding),
        "properties": {
            "cwe": list(finding.cwe),
            "remediation": finding.remediation,
            "needsReview": finding.needs_review,
        },
    }


def render_sarif(document: ReportDocument) -> str:
    """Serialise a ReportDocument into SARIF 2.1.0 JSON format."""
    # Deterministic set of rules: all known rules or rules referenced by findings
    referenced_rule_ids = {f.rule_id for f in document.findings}
    all_rule_ids = sorted(set(RULES_BY_ID.keys()) | referenced_rule_ids)

    rule_records = [_build_rule_record(rid) for rid in all_rule_ids]
    rule_index_map = {rid: idx for idx, rid in enumerate(all_rule_ids)}

    results = [_build_result(f, rule_index_map[f.rule_id]) for f in document.findings]

    is_successful = (
        document.coverage.files_unreadable == 0 and document.coverage.files_with_errors == 0
    )

    notifications: list[dict[str, Any]] = []
    sorted_failures = sorted(
        document.coverage.parse_failures,
        key=lambda f: (f.file.as_posix(), f.kind, f.name),
    )
    for failure in sorted_failures:
        notifications.append(
            {
                "message": {
                    "text": (
                        f"Parse failure in {failure.file.as_posix()}: "
                        f"{failure.kind} {failure.name}".strip()
                    )
                },
                "level": "error",
                "descriptor": {"id": "PARSER_ERROR"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": failure.file.as_posix(),
                                "uriBaseId": "%SRCROOT%",
                            }
                        }
                    }
                ],
            }
        )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "vigilloo",
                "version": document.metadata.engine_version,
                "informationUri": TOOL_INFORMATION_URI,
                "rules": rule_records,
            }
        },
        "invocations": [
            {
                "executionSuccessful": is_successful,
                "toolExecutionNotifications": notifications,
            }
        ],
        "results": results,
    }

    payload = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [run],
    }

    return json.dumps(payload, indent=2) + "\n"
