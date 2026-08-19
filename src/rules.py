"""Rule definitions and finding assembly.

Fully deterministic. Same project, same ruleset, same findings, every time.
"""

import hashlib
from dataclasses import dataclass

from .graph import Project
from .laravel.vocabulary import (
    CODE_EXECUTION_RULE,
    COMMAND_INJECTION_RULE,
    LARAVEL_BLADE_RAW_ECHO_RULE,
    LARAVEL_CSRF_EXCEPT_RULE,
    LARAVEL_INCONSISTENT_AUTHORIZATION_RULE,
    LARAVEL_VALIDATED_BYPASS_RULE,
    LARAVEL_FORM_REQUEST_TRUE_RULE,
    LARAVEL_ENV_OUTSIDE_CONFIG_RULE,
    LARAVEL_DEBUG_ENABLED_RULE,
    LARAVEL_APP_KEY_RULE,
    LARAVEL_TRUSTED_PROXIES_RULE,
    LARAVEL_SESSION_COOKIE_RULE,
    LARAVEL_UNSAFE_UPLOAD_RULE,
    LARAVEL_DEBUG_ARTIFACT_RULE,
    LARAVEL_WEAK_HASH_RULE,
    LARAVEL_WEAK_RANDOMNESS_RULE,
    LARAVEL_RAW_QUERY_RULE,
    LARAVEL_UNAUTHENTICATED_ROUTE_RULE,
    LARAVEL_NO_THROTTLE_RULE,
    LARAVEL_UNSIGNED_ROUTE_RULE,
    LARAVEL_DEAD_AUTHORIZATION_RULE,
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
import datetime
import fnmatch
from pathlib import Path
from .models import Finding, Span, PathStep, WalkStats
from .structural import find_structural_paths
from .taint import find_taint_paths

def _is_suppressed_by_config(project: Project, file_path: Path, rule_id: str) -> bool:
    for config in project.vigilloo_config.suppress:
        if config.rule != rule_id:
            continue
            
        if not fnmatch.fnmatch(str(file_path), config.path):
            continue
            
        if config.expires:
            try:
                expires_date = datetime.date.fromisoformat(config.expires)
                if datetime.date.today() > expires_date:
                    continue  # Suppression has expired
            except ValueError:
                pass  # Invalid date format, assume active
                
        return True
    return False

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


LARAVEL_RAW_QUERY = Rule(
    id=LARAVEL_RAW_QUERY_RULE,
    title="Raw Query Injection",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-89",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Use query bindings instead of string interpolation for the non-binding argument "
        "of raw builder methods (like whereRaw or DB::raw). For example, "
        "use whereRaw('price > ?', [$price])."
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


LARAVEL_BLADE_RAW_ECHO = Rule(
    id=LARAVEL_BLADE_RAW_ECHO_RULE,
    title="Blade Raw Echo XSS",
    severity="high",
    confidence=1.0,
    cwe=("CWE-79",),
    owasp=("A03:2021",),
    kind="TAINT",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Use {{ }} instead of {!! !!} to echo user-controlled data. Blade escapes {{ }} "
        "automatically, whereas {!! !!} renders the data raw, leading to Cross-Site Scripting."
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


LARAVEL_CSRF_EXCEPT = Rule(
    id=LARAVEL_CSRF_EXCEPT_RULE,
    title="CSRF Exception",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-352",),
    owasp=("A01:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Ensure that CSRF exceptions are absolutely necessary. If required, limit them to exact "
        "matches or highly constrained patterns. Do not use broad wildcards like `*` or `api/*`."
    ),
)


LARAVEL_UNAUTHENTICATED_ROUTE = Rule(
    id=LARAVEL_UNAUTHENTICATED_ROUTE_RULE,
    title="Unauthenticated State-Changing Route",
    severity="high",
    confidence=1.0,
    cwe=("CWE-306",),
    owasp=("A07:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Attach an authentication middleware (e.g. 'auth') to this route to ensure "
        "only logged-in users can perform state-changing operations."
    ),
)


LARAVEL_NO_THROTTLE = Rule(
    id=LARAVEL_NO_THROTTLE_RULE,
    title="Authentication Route Missing Rate Limiting",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-307",),
    owasp=("A07:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Attach the 'throttle' middleware to login, register, and password reset routes "
        "to protect against brute-force and credential stuffing attacks."
    ),
)


LARAVEL_UNSIGNED_ROUTE = Rule(
    id=LARAVEL_UNSIGNED_ROUTE_RULE,
    title="Public Action Route Missing Signature",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-345",),
    owasp=("A08:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Attach the 'signed' middleware to public action routes (like unsubscribe, confirm, approve) "
        "to ensure the URL was generated by your application and not tampered with."
    ),
)


LARAVEL_DEAD_AUTHORIZATION = Rule(
    id=LARAVEL_DEAD_AUTHORIZATION_RULE,
    title="Dead Authorization Policy",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-285",),
    owasp=("A01:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Remove this unreferenced policy method or wire it up to a route or action. "
        "A written but unwired policy is a strong oversight signal."
    ),
)


LARAVEL_INCONSISTENT_AUTHORIZATION = Rule(
    id=LARAVEL_INCONSISTENT_AUTHORIZATION_RULE,
    title="Inconsistent Authorization",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-285",),
    owasp=("A01:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "A resource controller has authorization checks in some actions but not others. "
        "This is a strong signal of an overlooked authorization check rather than "
        "intentional public access."
    ),
)


LARAVEL_VALIDATED_BYPASS = Rule(
    id=LARAVEL_VALIDATED_BYPASS_RULE,
    title="Validated Data Bypass",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-20",),
    owasp=("A03:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Using `$request->all()` after validation bypasses the validation filtering. "
        "Use `$request->validated()` instead."
    ),
)


LARAVEL_ENV_OUTSIDE_CONFIG = Rule(
    id=LARAVEL_ENV_OUTSIDE_CONFIG_RULE,
    title="env() Outside Config",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-1188",),
    owasp=("A05:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Calling env() outside config/ directories returns null when configuration is cached. "
        "Move the env() call to a config file and use config() to read it instead."
    ),
)


LARAVEL_FORM_REQUEST_TRUE = Rule(
    id=LARAVEL_FORM_REQUEST_TRUE_RULE,
    title="Form Request Bypasses Authorization",
    severity="high",
    confidence=1.0,
    cwe=("CWE-285",),
    owasp=("A01:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "A FormRequest guarding a state-changing model-bound action unconditionally returns true "
        "from its authorize() method. This disables authorization for the action. "
        "Implement a proper authorization check using policies."
    ),
)


LARAVEL_DEBUG_ENABLED = Rule(
    id=LARAVEL_DEBUG_ENABLED_RULE,
    title="Laravel Debug Mode Enabled in Production",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-489",),
    owasp=("A05:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "APP_DEBUG=true is enabled, exposing stack traces and environment variables, which can lead to RCE (Ignition, CVE-2021-3129). "
        "Set APP_DEBUG=false in production environments."
    ),
)


LARAVEL_APP_KEY = Rule(
    id=LARAVEL_APP_KEY_RULE,
    title="Laravel APP_KEY Missing or Insecure",
    severity="critical",
    confidence=1.0,
    cwe=("CWE-321",),
    owasp=("A02:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "APP_KEY is missing, empty, framework-default, or committed to version control. This breaks session encryption and can lead to RCE (CVE-2018-15133). "
        "Generate a unique APP_KEY using `php artisan key:generate` and do not commit the .env file."
    ),
)


LARAVEL_TRUSTED_PROXIES = Rule(
    id=LARAVEL_TRUSTED_PROXIES_RULE,
    title="Insecure TrustedProxies Configuration",
    severity="high",
    confidence=1.0,
    cwe=("CWE-348",),
    owasp=("A05:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Trusting all proxies ('*') allows attackers to spoof the client IP address (e.g. via X-Forwarded-For), "
        "bypassing IP-based restrictions and throttling. Specify a strict list of trusted proxy IPs."
    ),
)


LARAVEL_SESSION_COOKIE = Rule(
    id=LARAVEL_SESSION_COOKIE_RULE,
    title="Insecure Session Cookie Flags",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-614",),
    owasp=("A05:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Session cookies must have 'secure', 'http_only', and a strong 'same_site' policy to prevent "
        "interception, XSS theft, and CSRF attacks. Ensure these flags are properly configured in config/session.php."
    ),
)


LARAVEL_UNSAFE_UPLOAD = Rule(
    id=LARAVEL_UNSAFE_UPLOAD_RULE,
    title="Unsafe File Upload",
    severity="high",
    confidence=1.0,
    cwe=("CWE-434",),
    owasp=("A04:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Using getClientOriginalName() for file uploads is unsafe because the filename is user-controlled. "
        "It can lead to directory traversal, overwriting existing files, or XSS. "
        "Use a generated filename like the default store() behavior, or hashName()."
    ),
)


LARAVEL_DEBUG_ARTIFACT = Rule(
    id=LARAVEL_DEBUG_ARTIFACT_RULE,
    title="Debug Artifact in Production Code",
    severity="low",
    confidence=1.0,
    cwe=("CWE-489",),
    owasp=("A05:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "Debug functions like dd(), dump(), ray(), and var_dump() should not be present in non-test code. "
        "They can expose sensitive internal state or disrupt application flow."
    ),
)


LARAVEL_WEAK_HASH = Rule(
    id=LARAVEL_WEAK_HASH_RULE,
    title="Weak Password Hashing",
    severity="high",
    confidence=1.0,
    cwe=("CWE-328",),
    owasp=("A02:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "md5() and sha1() are cryptographically weak and vulnerable to collision attacks. "
        "For passwords, use Hash::make() which uses strong algorithms like bcrypt or argon2 by default."
    ),
)


LARAVEL_WEAK_RANDOMNESS = Rule(
    id=LARAVEL_WEAK_RANDOMNESS_RULE,
    title="Weak Randomness for Tokens",
    severity="high",
    confidence=1.0,
    cwe=("CWE-338",),
    owasp=("A02:2021",),
    kind="STRUCTURAL",
    languages=("php",),
    frameworks=("laravel",),
    remediation=(
        "rand() and mt_rand() use predictable PRNGs. When generating tokens, salts, or passwords, "
        "use a cryptographically secure pseudo-random number generator (CSPRNG) like random_bytes() or Str::random()."
    ),
)


VIGILLOO_BARE_IGNORE = Rule(
    id="vigilloo.bare-ignore",
    title="Bare or invalid suppression comment",
    severity="medium",
    confidence=1.0,
    cwe=("CWE-1173",),
    owasp=("A06:2021-Vulnerable and Outdated Components",),
    kind="STRUCTURAL",
    languages=("php", "blade"),
    frameworks=("laravel", "generic"),
    remediation="Provide a valid rule ID and a justification, e.g., // vigilloo-ignore php.sql-injection -- this parameter is an enum",
)

_BY_ID: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        SQL_INJECTION,
        LARAVEL_RAW_QUERY,
        XSS,
        LARAVEL_BLADE_RAW_ECHO,
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
        LARAVEL_CSRF_EXCEPT,
        LARAVEL_UNAUTHENTICATED_ROUTE,
        LARAVEL_NO_THROTTLE,
        LARAVEL_UNSIGNED_ROUTE,
        LARAVEL_DEAD_AUTHORIZATION,
        LARAVEL_INCONSISTENT_AUTHORIZATION,
        LARAVEL_VALIDATED_BYPASS,
        LARAVEL_FORM_REQUEST_TRUE,
        LARAVEL_ENV_OUTSIDE_CONFIG,
        LARAVEL_DEBUG_ENABLED,
        LARAVEL_APP_KEY,
        LARAVEL_TRUSTED_PROXIES,
        LARAVEL_SESSION_COOKIE,
        LARAVEL_UNSAFE_UPLOAD,
        LARAVEL_DEBUG_ARTIFACT,
        LARAVEL_WEAK_HASH,
        LARAVEL_WEAK_RANDOMNESS,
        VIGILLOO_BARE_IGNORE,
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


def scan_project(
    project: Project,
    stats: WalkStats | None = None,
    baseline: set[str] | None = None,
) -> list[Finding]:
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

    # Build a fast lookup for valid suppressions
    # (file, rule_id, target_line) -> suppression
    valid_suppressions = {}
    for s in project.suppressions:
        if s.is_invalid:
            continue
        # A suppression on line N suppresses a finding on line N+1
        valid_suppressions[(s.file, s.rule_id, s.line + 1)] = s

    findings = []
    
    # Emit bare/invalid ignores as findings
    for s in project.suppressions:
        if s.is_invalid:
            findings.append(
                Finding(
                    rule_id=VIGILLOO_BARE_IGNORE.id,
                    severity=VIGILLOO_BARE_IGNORE.severity,
                    title=VIGILLOO_BARE_IGNORE.title,
                    cwe=VIGILLOO_BARE_IGNORE.cwe,
                    span=Span(s.file, s.line, 1, s.line, 1),
                    evidence_path=(PathStep("entry", Span(s.file, s.line, 1, s.line, 1), "// vigilloo-ignore...", rule_id=VIGILLOO_BARE_IGNORE.id),),
                    remediation=VIGILLOO_BARE_IGNORE.remediation,
                )
            )

    for (rule_id, sink_span), group_paths in paths_by_sink.items():
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
        def path_sort_key(path: list[PathStep]) -> tuple[float, int, str]:
            min_conf = min((getattr(step, "confidence", 1.0) for step in path), default=1.0)
            return (-min_conf, len(path), str(path))
            
        group_paths.sort(key=path_sort_key)
        
        primary_path = group_paths[0]
        
        if "vendor/" in str(primary_path[-1].span.file):
            continue

        alternative_paths = tuple(tuple(p) for p in group_paths[1:])

        path_severity = severity
        needs_review = False
        if rule.kind == "TAINT" and any(
            getattr(step, "confidence", 1.0) < 0.5 for step in primary_path
        ):
            path_severity = _SEVERITY_DOWN.get(path_severity, path_severity)
            needs_review = True

        if (primary_path[-1].span.file, rule.id, primary_path[-1].span.start_line) in valid_suppressions:
            continue
            
        if _is_suppressed_by_config(project, primary_path[-1].span.file, rule.id):
            continue

        f = Finding(
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
        if baseline is not None and f.fingerprint in baseline:
            continue
            
        findings.append(f)

    return sorted(findings, key=lambda f: (str(f.span.file), f.span.start_line, f.rule_id))
