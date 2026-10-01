"""Reachability analysis for vulnerable dependencies against the application knowledge graph."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .advisories import Advisory
from .lockfile import Package

if TYPE_CHECKING:
    from ..graph import Project


@dataclass(frozen=True)
class ReachabilityResult:
    """Reachability status and justification for a dependency finding."""

    reachable: bool
    reason: str
    rank: int  # 3: route-reachable, 2: app-referenced, 1: uncalled


def _get_target_namespaces(package: Package) -> tuple[str, ...]:
    """Get the namespace prefixes associated with a package."""
    if package.namespaces:
        return package.namespaces

    # Heuristic fallback based on package vendor/name
    name = package.name.lower()
    mapping = {
        "guzzlehttp/guzzle": ("GuzzleHttp",),
        "monolog/monolog": ("Monolog",),
        "laravel/framework": ("Illuminate",),
        "symfony/http-kernel": ("Symfony\\Component\\HttpKernel",),
        "symfony/http-foundation": ("Symfony\\Component\\HttpFoundation",),
        "league/flysystem": ("League\\Flysystem",),
        "phpoffice/phpspreadsheet": ("PhpOffice\\PhpSpreadsheet",),
        "phpunit/phpunit": ("PHPUnit",),
    }
    return mapping.get(name, ())


def check_reachability(
    package: Package,
    advisory: Advisory,
    project: "Project | None" = None,
) -> ReachabilityResult:
    """Determine if a vulnerable package or advisory is reachable from the application."""
    if project is None:
        # Without a graph, reachability cannot be determined
        return ReachabilityResult(
            reachable=False,
            reason="Knowledge graph unavailable: reachability uncomputed",
            rank=1,
        )

    target_namespaces = _get_target_namespaces(package)
    if not target_namespaces:
        return ReachabilityResult(
            reachable=False,
            reason="No namespace signatures extracted for package",
            rank=1,
        )

    # 1. Identify which application files reference any of the target namespaces
    referencing_files: dict[str, list[str]] = {}  # file_path -> list of referenced symbols

    for rel_path_obj, syms in project.symbols.items():
        rel_path = str(rel_path_obj)
        # Skip vendor files if parsed
        if rel_path.startswith("vendor/") or "/vendor/" in rel_path:
            continue

        matched_refs: list[str] = []
        # Check imports (use statements)
        for _, imported_fqn in syms.imports.items():
            for ns in target_namespaces:
                if imported_fqn.startswith(ns):
                    matched_refs.append(imported_fqn)

        # Check class parents and traits
        for _, cls_info in syms.classes.items():
            if cls_info.parent:
                for ns in target_namespaces:
                    if cls_info.parent.startswith(ns):
                        matched_refs.append(cls_info.parent)
            for trait in cls_info.traits:
                for ns in target_namespaces:
                    if trait.startswith(ns):
                        matched_refs.append(trait)

        if matched_refs:
            referencing_files[rel_path] = matched_refs

    if not referencing_files:
        return ReachabilityResult(
            reachable=False,
            reason="Uncalled: package code not referenced by application",
            rank=1,
        )

    # 2. Check if any referencing file is connected to an HTTP route
    # Inspect route controller actions
    route_matches: list[str] = []
    for route in project.routes:
        action = route.action_fqn
        if "@" in action:
            controller_class, _ = action.split("@", 1)
        elif "::" in action:
            controller_class, _ = action.split("::", 1)
        else:
            controller_class = action

        controller_file = None
        for path_obj, syms in project.symbols.items():
            for cls_name, cls_info in syms.classes.items():
                if cls_name == controller_class or cls_info.fqn.endswith(f"\\{controller_class}"):
                    controller_file = str(path_obj)
                    break
            if controller_file:
                break

        if controller_file and controller_file in referencing_files:
            matched_sym = referencing_files[controller_file][0]
            verb_str = "/".join(route.verbs) if route.verbs else "ANY"
            route_matches.append(
                f"Reachable from {verb_str} {route.uri} via {controller_class} (uses {matched_sym})"
            )

    if route_matches:
        return ReachabilityResult(
            reachable=True,
            reason=route_matches[0],
            rank=3,
        )

    # 3. Referenced in application code, but no direct route mapping found
    first_file, refs = next(iter(referencing_files.items()))
    return ReachabilityResult(
        reachable=True,
        reason=f"Referenced in application file {first_file} (uses {refs[0]})",
        rank=2,
    )
