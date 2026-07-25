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
    """Assemble findings from every taint path the analysis produced."""
    findings = []
    for path in find_taint_paths(project, stats=stats):
        # ponytail: the rule is chosen by the sink's file extension. That works
        # only because the two sink sets are disjoint by construction - html
        # sinks are echo statements that exist only in project.blade, and
        # graph.py keeps .blade.php out of project.files - so no PHP file can
        # produce an html sink and no template can produce a sql one. The
        # third rule breaks that assumption: at which point PathStep carries
        # the rule identity from the walk and this branch goes away.
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
