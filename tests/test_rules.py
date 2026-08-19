import dataclasses
from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import _BY_ID, RULESET_HASH, _ruleset_hash, scan_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_every_implemented_rule_fires_on_the_fixture() -> None:
    findings = scan_project(load_project(FIXTURE))
    by_rule = {f.rule_id for f in findings}
    assert by_rule == {
        'laravel.missing-authorization', 
        'laravel.no-throttle', 
        'laravel.env-outside-config', 
        'laravel.validated-bypass', 
        'laravel.raw-query', 
        'laravel.unauthenticated-route', 
        'laravel.csrf-except', 
        'laravel.dead-authorization', 
        'laravel.unsigned-route', 
        'laravel.blade-raw-echo', 
        'laravel.inconsistent-authorization', 
        'laravel.form-request-true', 
        'laravel.mass-assignment',
        'vigilloo.bare-ignore'
    }

    minimal_findings = scan_project(load_project(FIXTURE))
    finding = next(
        f
        for f in minimal_findings
        if f.rule_id == "laravel.raw-query" and f.span.file.name == "OrderRepository.php"
    )
    assert finding.severity == "critical"
    assert finding.cwe == ("CWE-89",)
    assert finding.span.file.name == "OrderRepository.php"
    assert len(finding.evidence_path) == 4
    assert finding.remediation


def test_ruleset_hash_tracks_the_rules_and_not_their_order() -> None:
    """A stored scan's ruleset_hash is only useful if a changed rule moves it."""
    assert _ruleset_hash(dict(reversed(list(_BY_ID.items())))) == RULESET_HASH

    for field in ("id", "severity", "cwe"):
        rule = _BY_ID["laravel.blade-raw-echo"]
        changed = dataclasses.replace(rule, **{field: ("CWE-1",) if field == "cwe" else "x"})
        assert _ruleset_hash({**_BY_ID, "laravel.blade-raw-echo": changed}) != RULESET_HASH


def test_findings_are_stable_across_runs() -> None:
    a = scan_project(load_project(FIXTURE))
    b = scan_project(load_project(FIXTURE))
    assert [f.id for f in a] == [f.id for f in b]
    assert [f.fingerprint for f in a] == [f.fingerprint for f in b]


def test_fingerprint_is_independent_of_how_the_root_was_spelled() -> None:
    """A relative and an absolute scan of the same code must share a baseline."""
    relative = scan_project(load_project(FIXTURE))
    absolute = scan_project(load_project(FIXTURE.resolve()))
    assert [f.fingerprint for f in relative] == [f.fingerprint for f in absolute]


def test_rule_dataclass_shape_is_fully_populated() -> None:
    for rule in _BY_ID.values():
        assert rule.id
        assert rule.title
        assert rule.severity in {"critical", "high", "medium", "low", "info"}
        assert 0.0 <= rule.confidence <= 1.0
        assert rule.cwe
        assert rule.owasp
        assert rule.kind in {"TAINT", "STRUCTURAL", "CONFIG", "DEPENDENCY", "SECRET"}
        assert rule.languages
        assert rule.frameworks
        assert rule.remediation
