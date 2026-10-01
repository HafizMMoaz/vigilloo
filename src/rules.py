"""Rule definitions and finding assembly.

Backward-compatibility shim re-exporting vigilloo.security.rules.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from .security import rules as _target
from .security.rules import (
    _BY_ID,
    CODE_EXECUTION,
    COMMAND_INJECTION,
    LARAVEL_APP_KEY,
    LARAVEL_BLADE_RAW_ECHO,
    LARAVEL_CSRF_EXCEPT,
    LARAVEL_DEAD_AUTHORIZATION,
    LARAVEL_DEBUG_ARTIFACT,
    LARAVEL_DEBUG_ENABLED,
    LARAVEL_ENV_OUTSIDE_CONFIG,
    LARAVEL_FORM_REQUEST_TRUE,
    LARAVEL_INCONSISTENT_AUTHORIZATION,
    LARAVEL_NO_THROTTLE,
    LARAVEL_RAW_QUERY,
    LARAVEL_SESSION_COOKIE,
    LARAVEL_TRUSTED_PROXIES,
    LARAVEL_UNAUTHENTICATED_ROUTE,
    LARAVEL_UNSAFE_UPLOAD,
    LARAVEL_UNSIGNED_ROUTE,
    LARAVEL_VALIDATED_BYPASS,
    LARAVEL_WEAK_HASH,
    LARAVEL_WEAK_RANDOMNESS,
    LDAP_INJECTION,
    LOG_INJECTION,
    MASS_ASSIGNMENT,
    MISSING_AUTHORIZATION,
    OPEN_REDIRECT,
    PATH_TRAVERSAL,
    RULES_BY_ID,
    RULESET_HASH,
    SQL_INJECTION,
    SSRF,
    VIGILLOO_BARE_IGNORE,
    XPATH_INJECTION,
    XSS,
    Rule,
    _ruleset_hash,
    scan_project,
)

if TYPE_CHECKING:
    _Base = object
else:
    _Base = sys.modules[__name__].__class__


class _RulesShim(_Base):
    """Shim proxy ensuring dynamic modifications propagate to vigilloo.security.rules."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_target, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(_target, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _RulesShim  # type: ignore[assignment]

__all__ = [
    "CODE_EXECUTION",
    "COMMAND_INJECTION",
    "LARAVEL_APP_KEY",
    "LARAVEL_BLADE_RAW_ECHO",
    "LARAVEL_CSRF_EXCEPT",
    "LARAVEL_DEAD_AUTHORIZATION",
    "LARAVEL_DEBUG_ARTIFACT",
    "LARAVEL_DEBUG_ENABLED",
    "LARAVEL_ENV_OUTSIDE_CONFIG",
    "LARAVEL_FORM_REQUEST_TRUE",
    "LARAVEL_INCONSISTENT_AUTHORIZATION",
    "LARAVEL_NO_THROTTLE",
    "LARAVEL_RAW_QUERY",
    "LARAVEL_SESSION_COOKIE",
    "LARAVEL_TRUSTED_PROXIES",
    "LARAVEL_UNAUTHENTICATED_ROUTE",
    "LARAVEL_UNSAFE_UPLOAD",
    "LARAVEL_UNSIGNED_ROUTE",
    "LARAVEL_VALIDATED_BYPASS",
    "LARAVEL_WEAK_HASH",
    "LARAVEL_WEAK_RANDOMNESS",
    "LDAP_INJECTION",
    "LOG_INJECTION",
    "MASS_ASSIGNMENT",
    "MISSING_AUTHORIZATION",
    "OPEN_REDIRECT",
    "PATH_TRAVERSAL",
    "RULESET_HASH",
    "RULES_BY_ID",
    "Rule",
    "SQL_INJECTION",
    "SSRF",
    "VIGILLOO_BARE_IGNORE",
    "XPATH_INJECTION",
    "XSS",
    "_BY_ID",
    "_ruleset_hash",
    "scan_project",
]
