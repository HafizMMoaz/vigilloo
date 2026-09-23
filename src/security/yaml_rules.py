"""Declarative YAML rule loader and models for security engine."""

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..rules import Rule


@dataclass(frozen=True)
class DeclarativeRule:
    """Declarative representation of a security rule loaded from YAML."""

    id: str
    title: str
    severity: str
    confidence: float = 1.0
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    kind: str = "TAINT"
    languages: tuple[str, ...] = ("php",)
    frameworks: tuple[str, ...] = ("laravel",)
    remediation: str = ""
    taint_kind: str | None = None
    sources: tuple[str, ...] = ()
    sinks: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    require_reachable_from: tuple[str, ...] = ()

    def to_rule(self) -> Rule:
        """Convert declarative rule into an engine Rule instance."""
        return Rule(
            id=self.id,
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            cwe=self.cwe,
            owasp=self.owasp,
            kind=self.kind,
            languages=self.languages,
            frameworks=self.frameworks,
            remediation=self.remediation,
        )


def load_yaml_rule(source: str | Path) -> DeclarativeRule | None:
    """Load a single declarative rule from YAML string or file.

    Malformed YAML or missing required fields return None, so bad rules
    never crash a scan.
    """
    try:
        if isinstance(source, Path):
            content = source.read_text(encoding="utf-8")
        else:
            content = source

        raw = yaml.safe_load(content)
        if not isinstance(raw, dict):
            return None

        rule_id = raw.get("id")
        severity = raw.get("severity")
        if not rule_id or not severity:
            return None

        title = raw.get("title") or rule_id.replace(".", " ").replace("-", " ").title()
        confidence = float(raw.get("confidence", 1.0))
        cwe_raw = raw.get("cwe", ())
        cwe = tuple(cwe_raw) if isinstance(cwe_raw, list) else (str(cwe_raw),)
        owasp_raw = raw.get("owasp", ())
        owasp = tuple(owasp_raw) if isinstance(owasp_raw, list) else (str(owasp_raw),)
        kind = raw.get("kind", "TAINT").upper()

        langs_raw = raw.get("languages", ("php",))
        languages = tuple(langs_raw) if isinstance(langs_raw, list) else (str(langs_raw),)

        fw_raw = raw.get("frameworks", ("laravel",))
        frameworks = tuple(fw_raw) if isinstance(fw_raw, list) else (str(fw_raw),)

        remediation = raw.get("remediation", "").strip()

        sources = tuple(raw.get("sources", ()))
        sinks = tuple(raw.get("sinks", ()))
        sanitizers = tuple(raw.get("sanitizers", ()))
        reachable = tuple(raw.get("require_reachable_from", ()))

        return DeclarativeRule(
            id=rule_id,
            title=title,
            severity=severity,
            confidence=confidence,
            cwe=cwe,
            owasp=owasp,
            kind=kind,
            languages=languages,
            frameworks=frameworks,
            remediation=remediation,
            taint_kind=raw.get("taint_kind"),
            sources=sources,
            sinks=sinks,
            sanitizers=sanitizers,
            require_reachable_from=reachable,
        )
    except Exception:
        return None


def load_yaml_rules_from_dir(
    directory: Path,
    failures: dict[str, str] | None = None,
) -> list[DeclarativeRule]:
    """Load all declarative YAML rules from a directory with fault isolation."""
    if not directory.is_dir():
        return []

    rules: list[DeclarativeRule] = []
    patterns = ("*.yml", "*.yaml")
    rule_files: list[Path] = []
    for pattern in patterns:
        rule_files.extend(directory.glob(pattern))

    for rule_file in sorted(rule_files):
        try:
            rule = load_yaml_rule(rule_file)
            if rule is not None:
                rules.append(rule)
            else:
                if failures is not None:
                    failures[str(rule_file)] = "Malformed YAML rule or missing required fields"
        except Exception as exc:
            if failures is not None:
                failures[str(rule_file)] = str(exc)

    return rules
