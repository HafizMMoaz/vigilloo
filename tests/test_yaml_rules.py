"""Tests for declarative YAML rules loader and models."""

from pathlib import Path

from vigilloo.rules import LARAVEL_RAW_QUERY
from vigilloo.security import (
    DeclarativeRule,
    load_yaml_rule,
    load_yaml_rules_from_dir,
)

RULES_DIR = Path("src/laravel/rules")


def test_load_sql_injection_yaml_rule() -> None:
    yml_path = RULES_DIR / "sql_injection.yml"
    assert yml_path.exists()

    drule = load_yaml_rule(yml_path)
    assert drule is not None
    assert isinstance(drule, DeclarativeRule)
    assert drule.id == "php.sql-injection"
    assert drule.title == "SQL Injection"
    assert drule.severity == "critical"
    assert drule.cwe == ("CWE-89",)
    assert drule.owasp == ("A03:2021",)
    assert drule.kind == "TAINT"
    assert drule.taint_kind == "sql"

    rule = drule.to_rule()
    assert rule.id == "php.sql-injection"
    assert rule.severity == "critical"


def test_load_raw_query_yaml_rule() -> None:
    yml_path = RULES_DIR / "raw_query.yml"
    assert yml_path.exists()

    drule = load_yaml_rule(yml_path)
    assert drule is not None
    assert drule.id == LARAVEL_RAW_QUERY.id
    assert drule.severity == LARAVEL_RAW_QUERY.severity
    assert drule.cwe == LARAVEL_RAW_QUERY.cwe


def test_load_yaml_rules_from_directory() -> None:
    rules = load_yaml_rules_from_dir(RULES_DIR)
    assert len(rules) >= 2
    rule_ids = {r.id for r in rules}
    assert "php.sql-injection" in rule_ids
    assert "laravel.raw-query" in rule_ids


def test_malformed_yaml_rule_is_disabled_and_recorded(tmp_path: Path) -> None:
    bad_rule = tmp_path / "bad_rule.yml"
    bad_rule.write_text("id: only.id.missing.severity\n---\n::invalid yaml::", encoding="utf-8")

    good_rule = tmp_path / "good_rule.yml"
    good_rule.write_text("id: test.rule\nseverity: high\n", encoding="utf-8")

    failures: dict[str, str] = {}
    rules = load_yaml_rules_from_dir(tmp_path, failures=failures)

    assert len(rules) == 1
    assert rules[0].id == "test.rule"
    assert str(bad_rule) in failures
