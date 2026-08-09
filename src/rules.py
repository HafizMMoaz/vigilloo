"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

import hashlib
from dataclasses import dataclass

from .graph import Project
from .laravel.vocabulary import (
    MASS_ASSIGNMENT_RULE,
    MISSING_AUTHORIZATION_RULE,
    SQL_INJECTION_RULE,
    XSS_RULE,
)
from .models import Finding, WalkStats
from .structural import find_structural_paths
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

MISSING_AUTHORIZATION = Rule(
    id=MISSING_AUTHORIZATION_RULE,
    title="Missing Authorization on Model-Bound Route",
    severity="high",
    cwe=("CWE-639",),
    remediation=(
        "Add $this->authorize('view', $model) as the first statement of the "
        "action, or attach can:view,model middleware to the route. "
        "Authenticating a request says who the caller is; it never says which "
        "records that caller may read."
    ),
)

_BY_ID: dict[str, Rule] = {
    rule.id: rule for rule in (SQL_INJECTION, XSS, MASS_ASSIGNMENT, MISSING_AUTHORIZATION)
}


def _ruleset_hash(rules: dict[str, Rule]) -> str:
    """Content-derive an identity for the rule table.

    Sorted by id, so it does not depend on dict iteration order, and taken over the whole
    frozen dataclass repr, so any field change moves it: id, severity and cwe, and the prose
    fields too, since those are stored on every finding.
    """
    return hashlib.sha256(
        "\n".join(repr(rules[rule_id]) for rule_id in sorted(rules)).encode()
    ).hexdigest()[:16]


# Stored on every scan, so an old row can be told apart from one today's ruleset would produce
# (docs/17-database: ruleset_hash plus engine_version are what make a result reproducible). The
# store never computes it, because it sits below the security engine and must not learn what a
# rule is; the CLI reads it here and carries it down.
RULESET_HASH: str = _ruleset_hash(_BY_ID)


def scan_project(project: Project, stats: WalkStats | None = None) -> list[Finding]:
    """Assemble findings from every evidence path the analysis produced.

    Two producers, not one: taint paths and structural paths. Both yield the
    same shape and both name their rule on the final step, so the dispatch below
    does not need to know which produced what.
    """
    # Group paths by (rule_id, sink_span) to determine console-only reachability
    from collections import defaultdict
    paths_by_sink = defaultdict(list)
    for path in find_taint_paths(project, stats=stats) + find_structural_paths(project):
        if not path:
            continue
        rule_id = path[-1].rule_id
        sink_span = path[-1].span
        paths_by_sink[(rule_id, sink_span)].append(path)

    _SEVERITY_DOWN = {
        "critical": "high",
        "high": "medium",
        "medium": "low",
        "low": "info",
        "info": "info",
    }

    findings = []
    for (rule_id, sink_span), group_paths in paths_by_sink.items():
        rule = _BY_ID.get(rule_id)
        if rule is None:
            continue
            
        # If no path in the group has an HTTP entry point (but does have an entry point), it's console-only
        has_entry = any(
            path[0].role == "entry" and str(path[0].note).endswith("entry point") 
            for path in group_paths
        )
        has_http_entry = any(
            path[0].note == "HTTP entry point" for path in group_paths
        )
        
        severity = rule.severity
        if has_entry and not has_http_entry:
            severity = _SEVERITY_DOWN.get(severity, severity)

        for path in group_paths:
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=severity,
                    title=rule.title,
                    cwe=rule.cwe,
                    span=path[-1].span,
                    evidence_path=tuple(path),
                    remediation=rule.remediation,
                )
            )

    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
