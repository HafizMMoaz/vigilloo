"""Structural findings: vulnerabilities that are a property of the wiring.

Backward-compatibility shim re-exporting vigilloo.security.structural.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from .security import structural as _target
from .security.structural import (
    _AUTHORIZE_METHODS,
    _binding,
    _calls_authorization,
    _config_rules_paths,
    _controller_authorizes,
    _csrf_except_paths,
    _dead_authorization_paths,
    _debug_artifact_paths,
    _env_outside_config_paths,
    _extract_csrf_except,
    _form_request_authorizes,
    _form_request_returns_true,
    _inconsistent_authorization_paths,
    _is_state_changing,
    _missing_authorization,
    _no_throttle_paths,
    _signature,
    _unauthenticated_route_paths,
    _unsafe_upload_paths,
    _unsigned_route_paths,
    _validated_bypass_paths,
    _weak_hash_paths,
    _weak_randomness_paths,
    find_structural_paths,
)

if TYPE_CHECKING:
    _Base = object
else:
    _Base = sys.modules[__name__].__class__


class _StructuralShim(_Base):
    """Shim proxy ensuring dynamic modifications propagate to vigilloo.security.structural."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_target, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(_target, name, value)
        super().__setattr__(name, value)


sys.modules[__name__].__class__ = _StructuralShim  # type: ignore[assignment]

__all__ = [
    "_AUTHORIZE_METHODS",
    "_binding",
    "_calls_authorization",
    "_config_rules_paths",
    "_controller_authorizes",
    "_csrf_except_paths",
    "_dead_authorization_paths",
    "_debug_artifact_paths",
    "_env_outside_config_paths",
    "_extract_csrf_except",
    "_form_request_authorizes",
    "_form_request_returns_true",
    "_inconsistent_authorization_paths",
    "_is_state_changing",
    "_missing_authorization",
    "_no_throttle_paths",
    "_signature",
    "_unauthenticated_route_paths",
    "_unsafe_upload_paths",
    "_unsigned_route_paths",
    "_validated_bypass_paths",
    "_weak_hash_paths",
    "_weak_randomness_paths",
    "find_structural_paths",
]
