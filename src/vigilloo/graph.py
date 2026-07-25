"""In-memory project graph: files, symbols, classes and routes.

ponytail: in-memory only, rebuilt per run. SQLite persistence buys
incrementality, which this slice does not need - see docs 17-database.
"""

from dataclasses import dataclass, field
from pathlib import Path

from vigilloo.laravel.routes import extract_routes
from vigilloo.models import Route, Symbol
from vigilloo.parser import ParsedFile, parse_php
from vigilloo.symbols import ClassInfo, FileSymbols, extract_symbols

_EXCLUDED_DIRS = {"vendor", "node_modules", "storage", "bootstrap", ".git"}


@dataclass(frozen=True)
class Project:
    root: Path
    files: dict[Path, ParsedFile] = field(default_factory=dict)
    symbols: dict[Path, FileSymbols] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)
    failed: list[Path] = field(default_factory=list)

    def class_of(self, fqn: str) -> ClassInfo | None:
        return self.classes.get(fqn)

    def method(self, fqn: str) -> Symbol | None:
        class_fqn, _, method_name = fqn.rpartition("::")
        info = self.classes.get(class_fqn)
        return info.methods.get(method_name) if info else None

    def resolve_property_type(self, class_fqn: str, prop: str) -> str | None:
        info = self.classes.get(class_fqn)
        return info.properties.get(prop) if info else None

    def file_of_method(self, fqn: str) -> ParsedFile | None:
        method = self.method(fqn)
        return self.files.get(method.span.file) if method else None


def _php_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
    ]
    return sorted(found)  # sorted for determinism


def load_project(root: Path) -> Project:
    project = Project(root=root)

    for path in _php_files(root):
        try:
            parsed = parse_php(path)
        except OSError:
            project.failed.append(path)
            continue

        project.files[path] = parsed
        syms = extract_symbols(parsed)
        project.symbols[path] = syms
        project.classes.update(syms.classes)

        if path.parent.name == "routes":
            project.routes.extend(extract_routes(parsed, syms))

    project.routes.sort(key=lambda r: (str(r.span.file), r.span.start_line))
    return project
