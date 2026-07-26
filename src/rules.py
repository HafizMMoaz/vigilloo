"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

from dataclasses import dataclass

from .graph import Project
from .laravel.vocabulary import MASS_ASSIGNMENT_RULE, SQL_INJECTION_RULE, XSS_RULE
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
    id=SQL_INJECTION_RULE,
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
    id=XSS_RULE,
    title="Cross-Site Scripting",
    severity="high",
    cwe=("CWE-79",),
    remediation=(
        "Render the value with {{ }} instead of {!! !!}. Blade escapes {{ }} "
        "automatically. Reach for {!! !!} only for markup you generated "
        "yourself, never for anything derived from a request."
    ),
)


MASS_ASSIGNMENT = Rule(
    id=MASS_ASSIGNMENT_RULE,
    title="Mass Assignment",
    severity="high",
    cwe=("CWE-915",),
    remediation=(
        "Replace the model's $guarded = [] with an explicit $fillable listing "
        "only the columns a user may set, or pass $request->validated() / "
        "$request->only([...]) instead of $request->all()."
    ),
)

_BY_ID: dict[str, Rule] = {rule.id: rule for rule in (SQL_INJECTION, XSS, MASS_ASSIGNMENT)}


def scan_project(project: Project, stats: WalkStats | None = None) -> list[Finding]:
    """Assemble findings from every taint path the analysis produced."""
    findings = []
    for path in find_taint_paths(project, stats=stats):
        # The walk names the rule on the sink step. A path whose sink names a
        # rule this module does not define is dropped rather than guessed at:
        # emitting it under the wrong ID would put a finding in users'
        # baselines under an identity that never matches again.
        rule = _BY_ID.get(path[-1].rule_id)
        if rule is None:
            continue
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
