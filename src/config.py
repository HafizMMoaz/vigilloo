import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ProjectConfig:
    name: str = ""
    framework: str = "laravel"


@dataclass(frozen=True)
class ScanConfig:
    exclude: list[str] = field(default_factory=list)
    severity: str = "medium"
    fail_on: str = "high"


@dataclass(frozen=True)
class RulesConfig:
    disable: list[str] = field(default_factory=list)
    custom_dir: str | None = None


@dataclass(frozen=True)
class TaintConfig:
    sources: list[dict[str, Any]] = field(default_factory=list)
    sanitizers: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class AiConfig:
    enabled: bool = False
    provider: str = ""
    model: str = ""
    budget_usd: float = 0.0


@dataclass(frozen=True)
class SuppressConfig:
    rule: str
    path: str
    reason: str = ""
    expires: str = ""


@dataclass(frozen=True)
class VigillooConfig:
    version: int = 1
    project: ProjectConfig = field(default_factory=ProjectConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    taint: TaintConfig = field(default_factory=TaintConfig)
    ai: AiConfig = field(default_factory=AiConfig)
    suppress: list[SuppressConfig] = field(default_factory=list)

    @staticmethod
    def _merge_dict(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        merged = base.copy()
        for k, v in override.items():
            if isinstance(v, dict) and k in merged and isinstance(merged[k], dict):
                merged[k] = VigillooConfig._merge_dict(merged[k], v)
            else:
                merged[k] = v
        return merged

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            with path.open("r") as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            # Malformed file fails immediately with code 4. The diagnostic goes to stderr,
            # never stdout: stdout carries the scan report and must stay machine-readable.
            sys.stderr.write(f"Error: Malformed configuration file: {path}\n")
            sys.exit(4)

    @staticmethod
    def load(
        project_root: Path,
        cli_overrides: dict[str, Any] | None = None,
        user_config_path: Path | None = None,
        env_vars: dict[str, str] | None = None,
    ) -> "VigillooConfig":
        # 1. Defaults
        raw_config: dict[str, Any] = {
            "version": 1,
            "project": {"name": "", "framework": "laravel"},
            "scan": {"exclude": [], "severity": "medium", "fail_on": "high"},
            "rules": {"disable": [], "custom_dir": None},
            "taint": {"sources": [], "sanitizers": []},
            "ai": {"enabled": False, "provider": "", "model": "", "budget_usd": 0.0},
            "suppress": [],
        }

        # 2. User config (~/.config/vigilloo/vigilloo.yml)
        if user_config_path is None:
            user_config_path = Path.home() / ".config" / "vigilloo" / "vigilloo.yml"
        user_data = VigillooConfig._load_yaml(user_config_path)
        raw_config = VigillooConfig._merge_dict(raw_config, user_data)

        # 3. Project file (vigilloo.yml in root)
        project_data = VigillooConfig._load_yaml(project_root / "vigilloo.yml")
        raw_config = VigillooConfig._merge_dict(raw_config, project_data)

        # 4. Env vars (VIGILLOO_*)
        if env_vars is None:
            env_vars = dict(os.environ)

        env_overrides: dict[str, Any] = {}
        for k, v in env_vars.items():
            if k.startswith("VIGILLOO_"):
                # E.g., VIGILLOO_SCAN_SEVERITY=high -> env_overrides['scan']['severity'] = 'high'
                parts = k[len("VIGILLOO_") :].lower().split("_")
                current = env_overrides
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = v
        raw_config = VigillooConfig._merge_dict(raw_config, env_overrides)

        # 5. CLI flags
        if cli_overrides:
            raw_config = VigillooConfig._merge_dict(raw_config, cli_overrides)

        return VigillooConfig(
            version=raw_config.get("version", 1),
            project=ProjectConfig(**raw_config.get("project", {})),
            scan=ScanConfig(**raw_config.get("scan", {})),
            rules=RulesConfig(**raw_config.get("rules", {})),
            taint=TaintConfig(**raw_config.get("taint", {})),
            ai=AiConfig(**raw_config.get("ai", {})),
            suppress=[SuppressConfig(**s) for s in raw_config.get("suppress", [])],
        )
