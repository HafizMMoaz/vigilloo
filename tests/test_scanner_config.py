from pathlib import Path

import pytest

from vigilloo.config import VigillooConfig


def test_config_defaults(tmp_path: Path) -> None:
    config = VigillooConfig.load(project_root=tmp_path, user_config_path=tmp_path / "missing.yml")
    assert config.version == 1
    assert config.project.framework == "laravel"
    assert config.scan.severity == "medium"
    assert config.scan.fail_on == "high"
    assert config.scan.exclude == []


def test_config_user_config(tmp_path: Path) -> None:
    user_conf = tmp_path / "user.yml"
    user_conf.write_text("""
scan:
  severity: low
""")
    config = VigillooConfig.load(project_root=tmp_path, user_config_path=user_conf)
    assert config.scan.severity == "low"
    assert config.scan.fail_on == "high"  # default remains


def test_config_project_overrides_user(tmp_path: Path) -> None:
    user_conf = tmp_path / "user.yml"
    user_conf.write_text("scan:\n  severity: low\n  fail_on: critical\n")

    project_conf = tmp_path / "vigilloo.yml"
    project_conf.write_text("scan:\n  severity: high\n")

    config = VigillooConfig.load(project_root=tmp_path, user_config_path=user_conf)
    assert config.scan.severity == "high"  # Project override
    assert config.scan.fail_on == "critical"  # Inherited from user


def test_config_env_overrides_project(tmp_path: Path) -> None:
    project_conf = tmp_path / "vigilloo.yml"
    project_conf.write_text("scan:\n  severity: high\n")

    env_vars = {"VIGILLOO_SCAN_SEVERITY": "critical"}

    config = VigillooConfig.load(
        project_root=tmp_path, env_vars=env_vars, user_config_path=tmp_path / "missing.yml"
    )
    assert config.scan.severity == "critical"


def test_config_cli_overrides_all(tmp_path: Path) -> None:
    project_conf = tmp_path / "vigilloo.yml"
    project_conf.write_text("scan:\n  severity: high\n")
    env_vars = {"VIGILLOO_SCAN_SEVERITY": "critical"}
    cli_overrides = {"scan": {"severity": "low"}}

    config = VigillooConfig.load(
        project_root=tmp_path,
        cli_overrides=cli_overrides,
        env_vars=env_vars,
        user_config_path=tmp_path / "missing.yml",
    )
    assert config.scan.severity == "low"


def test_config_malformed_yaml_exits(tmp_path: Path) -> None:
    project_conf = tmp_path / "vigilloo.yml"
    project_conf.write_text("scan:\n  severity: [unclosed list")

    with pytest.raises(SystemExit) as exc:
        VigillooConfig.load(project_root=tmp_path, user_config_path=tmp_path / "missing.yml")

    assert exc.value.code == 4


def test_config_full_schema(tmp_path: Path) -> None:
    project_conf = tmp_path / "vigilloo.yml"
    project_conf.write_text("""
version: 1
project:
  name: test-app
scan:
  exclude: ["vendor/**"]
rules:
  disable: ["rule1"]
  custom_dir: ".rules"
ai:
  enabled: true
suppress:
  - rule: "php.xss"
    path: "tests/**"
    reason: "test code"
""")

    config = VigillooConfig.load(project_root=tmp_path, user_config_path=tmp_path / "missing.yml")
    assert config.project.name == "test-app"
    assert config.scan.exclude == ["vendor/**"]
    assert config.rules.disable == ["rule1"]
    assert config.rules.custom_dir == ".rules"
    assert config.ai.enabled is True
    assert len(config.suppress) == 1
    assert config.suppress[0].rule == "php.xss"
    assert config.suppress[0].path == "tests/**"
