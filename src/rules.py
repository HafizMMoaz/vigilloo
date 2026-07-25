"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

from dataclasses import dataclass

from .graph import Project
from .models import Finding, WalkStats
from .taint import find_taint_paths


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: tuple[str, ...]
    remediation: str


SQL_INJECTION = Rule(
    id="php.sql-injection",
    title="SQL Injection",
    severity="critical",
    cwe=("CWE-89",),
    remediation=(
        "Pass user input as a query binding rather than interpolating it into "
        "the SQL string, or validate it against an allowlist. For an ORDER BY "
        "direction: $dir = $sort === 'asc' ? 'asc' : 'desc';"
    ),
)

XSS = Rule(
    id="php.xss",
    title="Cross-Site Scripting",
    severity="high",
    cwe=("CWE-79",),
    remediation=(
        "Render the value with {{ }} instead of {!! !!}. Blade escapes {{ }} "
        "automatically. Reach for {!! !!} only for markup you generated "
        "yourself, never for anything derived from a request."
    ),
)


def scan_project(project: Project, stats: WalkStats | None = None) -> list[Finding]:
    """Run every rule over the project graph."""
    findings = []
    for path in find_taint_paths(project, stats=stats):
        rule = XSS if path[-1].span.file.name.endswith(".blade.php") else SQL_INJECTION
        findings.append(
            Finding(
                rule_id=rule.id,
                severity=rule.severity,
                title=rule.title,
                cwe=rule.cwe,
                span=path[-1].span,
                evidence_path=tuple(path),
                remediation=rule.remediation,
            )
        )
    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
