"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

from dataclasses import dataclass

from vigilloo.graph import Project
from vigilloo.models import Finding
from vigilloo.taint import find_taint_paths


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    remediation: str


SQL_INJECTION = Rule(
    id="php.sql-injection",
    title="SQL Injection",
    severity="critical",
    cwe=("CWE-89",),
    owasp=("A03:2021",),
    remediation=(
        "Pass user input as a query binding rather than interpolating it into "
        "the SQL string, or validate it against an allowlist. For an ORDER BY "
        "direction: $dir = $sort === 'asc' ? 'asc' : 'desc';"
    ),
)


def scan_project(project: Project) -> list[Finding]:
    """Run every rule over the project graph."""
    findings = [
        Finding(
            rule_id=SQL_INJECTION.id,
            severity=SQL_INJECTION.severity,
            title=SQL_INJECTION.title,
            cwe=SQL_INJECTION.cwe,
            span=path[-1].span,
            evidence_path=tuple(path),
            remediation=SQL_INJECTION.remediation,
        )
        for path in find_taint_paths(project)
    ]
    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
