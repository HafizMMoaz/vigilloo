"""Configuration loading for vigilloo.yml.

Backward-compatibility shim re-exporting vigilloo.workspace.config.
"""

from .workspace.config import (
    AiConfig,
    ProjectConfig,
    RulesConfig,
    ScanConfig,
    SuppressConfig,
    TaintConfig,
    VigillooConfig,
    check_config_file,
)

__all__ = [
    "AiConfig",
    "ProjectConfig",
    "RulesConfig",
    "ScanConfig",
    "SuppressConfig",
    "TaintConfig",
    "VigillooConfig",
    "check_config_file",
]
