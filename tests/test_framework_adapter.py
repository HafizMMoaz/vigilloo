"""Tests for FrameworkAdapter protocol conformance and LaravelAdapter."""

from pathlib import Path

from vigilloo.laravel.adapter import LaravelAdapter
from vigilloo.models import EntryPoint
from vigilloo.parser import ParsedFile
from vigilloo.rules import Rule
from vigilloo.sdk import (
    DetectionResult,
    FrameworkAdapter,
    FrameworkFacts,
    ProjectProfile,
)
from vigilloo.summaries import FunctionSummary


class StubFrameworkAdapter:
    """A minimal stub adapter to prove FrameworkAdapter is not Laravel-shaped."""

    name: str = "stub"

    def detect(self, project: ProjectProfile) -> DetectionResult:
        if (project.root / "stub.json").is_file():
            return DetectionResult(detected=True, framework="stub", version="1.0")
        return DetectionResult(detected=False, framework="stub")

    def extract(self, files: list[ParsedFile]) -> FrameworkFacts:
        return FrameworkFacts()

    def entry_points(self, facts: FrameworkFacts) -> list[EntryPoint]:
        return []

    def summaries(self) -> list[FunctionSummary]:
        return []

    def rules(self) -> list[Rule]:
        return []


def test_laravel_adapter_satisfies_protocol() -> None:
    adapter = LaravelAdapter()
    assert isinstance(adapter, FrameworkAdapter)
    assert adapter.name == "laravel"


def test_stub_adapter_satisfies_protocol() -> None:
    adapter = StubFrameworkAdapter()
    assert isinstance(adapter, FrameworkAdapter)
    assert adapter.name == "stub"


def test_laravel_detection_composer(tmp_path: Path) -> None:
    adapter = LaravelAdapter()

    profile_detected = ProjectProfile(
        root=tmp_path,
        composer={"require": {"laravel/framework": "^11.0"}},
    )
    result = adapter.detect(profile_detected)
    assert result.detected is True
    assert result.framework == "laravel"
    assert result.version == "^11.0"

    profile_not_detected = ProjectProfile(
        root=tmp_path,
        composer={"require": {"symfony/framework-bundle": "^6.0"}},
    )
    result_neg = adapter.detect(profile_not_detected)
    assert result_neg.detected is False


def test_laravel_detection_artisan_file(tmp_path: Path) -> None:
    adapter = LaravelAdapter()
    artisan = tmp_path / "artisan"
    artisan.write_text("<?php // artisan", encoding="utf-8")

    profile = ProjectProfile(root=tmp_path)
    result = adapter.detect(profile)
    assert result.detected is True
    assert result.framework == "laravel"


def test_laravel_rules_returns_laravel_prefixed_rules() -> None:
    adapter = LaravelAdapter()
    rules = adapter.rules()
    assert len(rules) > 0
    assert all(r.id.startswith("laravel.") for r in rules)
