"""Laravel FrameworkAdapter implementation."""

from ..models import EntryPoint
from ..parser import ParsedFile
from ..rules import RULES_BY_ID, Rule
from ..sdk.adapter import DetectionResult, FrameworkFacts, ProjectProfile
from ..summaries import FunctionSummary


class LaravelAdapter:
    name: str = "laravel"

    def detect(self, project: ProjectProfile) -> DetectionResult:
        if project.composer:
            req = project.composer.get("require", {})
            req_dev = project.composer.get("require-dev", {})
            if "laravel/framework" in req or "laravel/framework" in req_dev:
                ver = req.get("laravel/framework") or req_dev.get("laravel/framework")
                return DetectionResult(
                    detected=True, framework="laravel", version=ver, confidence=1.0
                )

        if (project.root / "artisan").is_file():
            return DetectionResult(detected=True, framework="laravel", version=None, confidence=0.9)

        for p in project.files:
            if p.name == "artisan" or p.parts[-2:] == ("routes", "web.php"):
                return DetectionResult(
                    detected=True, framework="laravel", version=None, confidence=0.8
                )

        return DetectionResult(detected=False, framework="laravel", version=None, confidence=0.0)

    def extract(self, files: list[ParsedFile]) -> FrameworkFacts:
        facts = FrameworkFacts()
        return facts

    def entry_points(self, facts: FrameworkFacts) -> list[EntryPoint]:
        return list(facts.entry_points)

    def summaries(self) -> list[FunctionSummary]:
        return []

    def rules(self) -> list[Rule]:
        return [rule for rule in RULES_BY_ID.values() if rule.id.startswith("laravel.")]
