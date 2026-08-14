"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

import hashlib
from dataclasses import dataclass

from .graph import Project
from .laravel.vocabulary import (
    CODE_EXECUTION_RULE,
    COMMAND_INJECTION_RULE,
    LDAP_INJECTION_RULE,
    LOG_INJECTION_RULE,
    MASS_ASSIGNMENT_RULE,
    MISSING_AUTHORIZATION_RULE,
    OPEN_REDIRECT_RULE,
    PATH_TRAVERSAL_RULE,
    SQL_INJECTION_RULE,
    SSRF_RULE,
    XPATH_INJECTION_RULE,
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
    confidence: float
    cwe: tuple[str, ...]
    owasp: tuple[str, ...]
    kind: str
    languages: tuple[str, ...]
    frameworks: tuple[str, ...]
    remediation: str


SQL_INJECTION = Rule(
    id=SQL_INJECTION_RULE,
    title="SQL Injection",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-89",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
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
    confidence=1.0,
    cwe=("CWE-79",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Render the value with {{ }} instead of {!! !!}. Blade escapes {{ }} "
        "automatically. Reach for {!! !!} only for markup you generated "
        "yourself, never for anything derived from a request."
    ),
)


COMMAND_INJECTION = Rule(
    id=COMMAND_INJECTION_RULE,
    title="Command Injection",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-78",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Avoid building shell commands with raw string interpolation of untrusted input. "
        "Use array arguments with Process::run(['command', $arg]) or "
        "sanitize input with escapeshellarg()."
    ),
)


CODE_EXECUTION = Rule(
    id=CODE_EXECUTION_RULE,
    title="Code Execution",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-94", "CWE-502"),
    owasp=("A03:2021", "A08:2021"),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Never pass untrusted input to eval(), unserialize(), create_function(), "
        "dynamic include/require, or callable callbacks. "
        "There is no sanitizer that makes this safe: redesign the call site to "
        "avoid executing attacker-controlled code entirely."
    ),
)


PATH_TRAVERSAL = Rule(
    id=PATH_TRAVERSAL_RULE,
    title="Path Traversal",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-22", "CWE-434"),
    owasp=("A01:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Validate the filename against a strict allowlist, or use basename() to "
        "strip directory components before using it in a filesystem operation. "
        "Ensure paths resolve to the intended directory."
    ),
)


SSRF = Rule(
    id=SSRF_RULE,
    title="Server-Side Request Forgery",
    severity="high",
    confidence=1.0,
    cwe=("CWE-918",),
    owasp=("A10:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Validate URLs against a strict allowlist of permitted hosts. "
        "Do not allow arbitrary user input to form the scheme or host of an outbound HTTP request."
    ),
)


MASS_ASSIGNMENT = Rule(
    id=MASS_ASSIGNMENT_RULE,
    title="Mass Assignment",
    severity="high",
    confidence=1.0,
    cwe=("CWE-915",),
    owasp=("A01:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
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
    confidence=1.0,
    cwe=("CWE-639",),
    owasp=("A01:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Add $this->authorize('view', $model) as the first statement of the "
        "action, or attach can:view,model middleware to the route. "
        "Authenticating a request says who the caller is; it never says which "
        "records that caller may read."
    ),
)

OPEN_REDIRECT = Rule(
    id=OPEN_REDIRECT_RULE,
    title="Open Redirect",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-601", "CWE-113"),
    owasp=("A01:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Validate the redirect URL against a strict allowlist of permitted destinations, "
        "or ensure it is a relative path (e.g. starts_with:/)."
    ),
)


LDAP_INJECTION = Rule(
    id=LDAP_INJECTION_RULE,
    title="LDAP Injection",
    severity="high",
    confidence=1.0,
    cwe=("CWE-90",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Escape user input before placing it in an LDAP search filter. "
        "Use ldap_escape() with appropriate flags for DN or filter contexts."
    ),
)


XPATH_INJECTION = Rule(
    id=XPATH_INJECTION_RULE,
    title="XPath Injection",
    severity="high",
    confidence=1.0,
    cwe=("CWE-643",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Avoid string concatenation when building XPath queries. Use bound variables if supported, "
        "or strictly validate and cast input to expected types before interpolation."
    ),
)


LOG_INJECTION = Rule(
    id=LOG_INJECTION_RULE,
    title="Log Injection",
    severity="low",
    confidence=1.0,
    cwe=("CWE-117",),
    owasp=("A09:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Sanitize user input before writing it to logs by removing or encoding newline characters "
        "to prevent log forging. Alternatively, use structured logging (e.g. JSON)."
    ),
)

_BY_ID: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        SQL_INJECTION,
        XSS,
        COMMAND_INJECTION,
        CODE_EXECUTION,
        PATH_TRAVERSAL,
        SSRF,
        MASS_ASSIGNMENT,
        MISSING_AUTHORIZATION,
        OPEN_REDIRECT,
        LDAP_INJECTION,
        XPATH_INJECTION,
        LOG_INJECTION,
    )
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
    _SEVERITY_UP = {
        "info": "low",
        "low": "medium",
        "medium": "high",
        "high": "critical",
        "critical": "critical",
    }

    findings = []
    for (rule_id, _), group_paths in paths_by_sink.items():
        rule = _BY_ID.get(rule_id)
        if rule is None:
            continue

        # If no path in the group has an HTTP entry point (but does have an entry point),
        # it's console-only
        has_entry = any(
            path[0].role == "entry" and str(path[0].note).endswith("entry point")
            for path in group_paths
        )
        has_http_entry = any(
            path[0].role == "entry" and str(path[0].note).startswith("HTTP") 
            for path in group_paths
        )
        has_unauth_http_entry = any(
            path[0].role == "entry" and "unauthenticated" in str(path[0].note) 
            for path in group_paths
        )

        severity = rule.severity
        if rule.kind == "TAINT":
            if has_unauth_http_entry:
                severity = _SEVERITY_UP.get(severity, severity)
            elif has_entry and not has_http_entry:
                severity = _SEVERITY_DOWN.get(severity, severity)

        # Path confidence is the minimum confidence of any step.
        # We want highest confidence first (sort by -min_conf),
        # then shortest length (len(path)),
        # then deterministic tie-breaker (str(path)).
        def path_sort_key(path):
            min_conf = min((getattr(step, "confidence", 1.0) for step in path), default=1.0)
            return (-min_conf, len(path), str(path))
            
        group_paths.sort(key=path_sort_key)
        
        primary_path = group_paths[0]
        
        if "vendor/" in str(primary_path[-1].span.file):
            continue

        alternative_paths = tuple(tuple(p) for p in group_paths[1:])

        path_severity = severity
        needs_review = False
        if rule.kind == "TAINT" and any(getattr(step, "confidence", 1.0) < 0.5 for step in primary_path):
            path_severity = _SEVERITY_DOWN.get(path_severity, path_severity)
            needs_review = True

        findings.append(
            Finding(
                rule_id=rule.id,
                severity=path_severity,
                title=rule.title,
                cwe=rule.cwe,
                span=primary_path[-1].span,
                evidence_path=tuple(primary_path),
                alternative_paths=alternative_paths,
                remediation=rule.remediation,
                needs_review=needs_review,
            )
        )

    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
