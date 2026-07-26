"""In-memory project graph: files, symbols, classes and routes.

ponytail: in-memory only, rebuilt per run. SQLite persistence buys
incrementality, which this slice does not need - see docs 17-database.
"""

from dataclasses import dataclass, field, replace
from pathlib import Path

from .laravel.blade import to_php
from .laravel.routes import extract_routes
from .models import Route, Symbol, WalkStats
from .parser import ParsedFile, parse_php, parse_source
from .symbols import ClassInfo, FileSymbols, extract_symbols, resolve_type_name

_EXCLUDED_DIRS = {"vendor", "node_modules", "storage", "bootstrap", ".git"}


@dataclass(frozen=True)
class Project:
    root: Path
    files: dict[Path, ParsedFile] = field(default_factory=dict)
    symbols: dict[Path, FileSymbols] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)
    blade: dict[Path, ParsedFile] = field(default_factory=dict)
    blade_lines: dict[Path, list[str]] = field(default_factory=dict)
    failed: list[Path] = field(default_factory=list)
    unparsed: list[Path] = field(default_factory=list)

    def method(self, fqn: str) -> Symbol | None:
        class_fqn, _, method_name = fqn.rpartition("::")
        info = self.classes.get(class_fqn)
        return info.methods.get(method_name) if info else None

    def resolve_property_type(self, class_fqn: str, prop: str) -> str | None:
        info = self.classes.get(class_fqn)
        return info.properties.get(prop) if info else None

    def resolve_class_name(self, file: Path, written: str) -> str | None:
        """Resolve a class name as written in `file` to its FQN.

        `User::create(...)` names the class at the call site, so this is all
        the resolution a static call needs - no receiver type inference.
        Returns None when the file has no symbol table, rather than guessing a
        global-namespace name that would not match any known class.
        """
        syms = self.symbols.get(file)
        if syms is None:
            return None
        return resolve_type_name(written, syms.namespace, syms.imports)

    def blade_line(self, path: Path, line: int) -> str:
        """The original Blade text of a 1-indexed line, for evidence snippets.

        Findings must quote what the developer wrote, not the PHP it was
        rewritten into. Out-of-range lines return empty rather than raising:
        a snippet is presentation, and it must never be able to abort a scan.
        """
        lines = self.blade_lines.get(path, [])
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""


def _php_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
        and not p.name.endswith(".blade.php")
    ]
    return sorted(found)  # sorted for determinism


def _blade_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.blade.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
    ]
    return sorted(found)  # sorted for determinism


def load_project(root: Path, stats: WalkStats | None = None) -> Project:
    project = Project(root=root)

    for path in _php_files(root):
        try:
            parsed = parse_php(path)
        except OSError:
            project.failed.append(path)
            continue

        # Store paths relative to the project root, not however the caller
        # spelled it. Span.file feeds Finding.id/.fingerprint (models.py), so
        # `vigilloo scan .` and `vigilloo scan /abs/path` must produce the
        # same identities for the same code, or every suppression baseline
        # silently stops matching depending on which form CI happened to use.
        rel_path = path.relative_to(root)
        parsed = replace(parsed, path=rel_path)

        # A syntax error degrades this file, it never aborts the scan - but
        # the gap in coverage must still be visible, so it is recorded even
        # though whatever symbols could be extracted are kept and used.
        if parsed.has_errors:
            project.unparsed.append(rel_path)

        project.files[rel_path] = parsed
        syms = extract_symbols(parsed)
        project.symbols[rel_path] = syms
        project.classes.update(syms.classes)

        # ponytail: routes are recognised only by living in a directory
        # literally named "routes" (Laravel's default routes/api.php,
        # routes/web.php). A Laravel 10+ split like routes/api/v1.php is
        # invisible to this rule. Deliberately not broadened for this slice;
        # cli.py's "no HTTP entry points discovered" warning is what keeps
        # that gap from being silent instead of a green report with nothing
        # scanned.
        if rel_path.parent.name == "routes":
            project.routes.extend(extract_routes(parsed, syms, stats))

    for path in _blade_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            project.failed.append(path)
            continue

        rel_path = path.relative_to(root)
        parsed = parse_source(rel_path, to_php(text).encode("utf-8"))

        # A template that will not parse degrades this file, never the scan.
        if parsed.has_errors:
            project.unparsed.append(rel_path)

        project.blade[rel_path] = parsed
        project.blade_lines[rel_path] = text.splitlines()

    project.routes.sort(key=lambda r: (str(r.span.file), r.span.start_line))
    return project
