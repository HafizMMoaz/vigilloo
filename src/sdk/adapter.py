"""FrameworkAdapter protocol and supporting types for framework plugins."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..models import EntryPoint, Route
from ..parser import ParsedFile
from ..rules import Rule
from ..summaries import FunctionSummary


@dataclass(frozen=True)
class ProjectProfile:
    root: Path
    composer: dict[str, Any] | None = None
    files: tuple[Path, ...] = ()


@dataclass(frozen=True)
class DetectionResult:
    detected: bool
    framework: str
    version: str | None = None
    confidence: float = 1.0


@dataclass
class FrameworkFacts:
    routes: list[Route] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    models: dict[str, Any] = field(default_factory=dict)
    middleware: dict[str, Any] = field(default_factory=dict)
    policies: dict[str, Any] = field(default_factory=dict)
    schema: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class FrameworkAdapter(Protocol):
    name: str

    def detect(self, project: ProjectProfile) -> DetectionResult: ...

    def extract(self, files: list[ParsedFile]) -> FrameworkFacts: ...

    def entry_points(self, facts: FrameworkFacts) -> list[EntryPoint]: ...

    def summaries(self) -> list[FunctionSummary]: ...

    def rules(self) -> list[Rule]: ...
