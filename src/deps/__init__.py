"""Dependency vulnerability analysis and SBOM generation."""

import json
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..graph import load_project
from .advisories import Advisory, load_advisories, match_package_advisories
from .lockfile import Package, parse_lockfile
from .reachability import ReachabilityResult, check_reachability
from .sbom import generate_cyclonedx_sbom, generate_spdx_sbom


@dataclass(frozen=True)
class DependencyFinding:
    """A vulnerable dependency finding with advisory and reachability details."""

    package: Package
    advisory: Advisory
    reachable: bool
    reach_reason: str
    rank: int


def scan_dependencies(
    path: Path,
    reachable_only: bool = False,
) -> tuple[list[Package], list[DependencyFinding]]:
    """Scan composer.lock in path for vulnerabilities and compute reachability."""
    lockfile = path / "composer.lock"
    packages = parse_lockfile(lockfile)
    advisories = load_advisories()

    # Attempt to load project graph for reachability
    project = None
    try:
        project = load_project(path)
    except Exception:
        project = None

    findings: list[DependencyFinding] = []
    for pkg in packages:
        pkg_advisories = match_package_advisories(pkg, advisories)
        for adv in pkg_advisories:
            reach = check_reachability(pkg, adv, project)
            if reachable_only and not reach.reachable:
                continue
            findings.append(
                DependencyFinding(
                    package=pkg,
                    advisory=adv,
                    reachable=reach.reachable,
                    reach_reason=reach.reason,
                    rank=reach.rank,
                )
            )

    # Sort findings: reachable (highest rank) first, then by CVSS descending, then package name
    findings.sort(
        key=lambda f: (
            -f.rank,
            -(f.advisory.cvss or 0.0),
            f.package.name,
        )
    )

    return packages, findings


def run_deps(
    path: Path,
    reachable_only: bool = False,
    sbom_format: str | None = None,
    output_file: Path | None = None,
    as_json: bool = False,
) -> int:
    """Execute the `vigilloo deps` CLI workflow."""
    console = Console(stderr=True) if as_json else Console()

    if not path.exists():
        console.print(f"[red]Error: path does not exist: {path}[/red]")
        return 2
    if not path.is_dir():
        console.print(f"[red]Error: not a directory: {path}[/red]")
        return 2

    lockfile = path / "composer.lock"
    if not lockfile.exists():
        console.print(f"[red]Error: composer.lock not found in {path}[/red]")
        return 2

    packages, findings = scan_dependencies(path, reachable_only=reachable_only)

    # SBOM generation branch
    if sbom_format:
        fmt = sbom_format.lower().strip()
        matched_dict: dict[str, list[tuple[Advisory, ReachabilityResult]]] = {}
        for f in findings:
            matched_dict.setdefault(f.package.name, []).append(
                (f.advisory, ReachabilityResult(f.reachable, f.reach_reason, f.rank))
            )

        if fmt in ("cyclonedx", "cyclonedx-json"):
            sbom_text = generate_cyclonedx_sbom(path.name or "project", packages, matched_dict)
        elif fmt in ("spdx", "spdx-json"):
            sbom_text = generate_spdx_sbom(path.name or "project", packages)
        else:
            console.print(
                f"[red]Error: unsupported SBOM format '{sbom_format}'. Use cyclonedx or spdx.[/red]"
            )
            return 2

        if output_file:
            output_file.write_text(sbom_text, encoding="utf-8")
            if not as_json:
                console.print(f"[green]Wrote SBOM ({fmt}) to {output_file}[/green]")
        else:
            print(sbom_text, end="")  # noqa: T201
        return 0

    if as_json:
        payload = {
            "path": str(path.resolve()),
            "packages_count": len(packages),
            "vulnerabilities_count": len(findings),
            "findings": [
                {
                    "package": f.package.name,
                    "version": f.package.version,
                    "is_dev": f.package.is_dev,
                    "license": f.package.license,
                    "advisory_id": f.advisory.id,
                    "cve": f.advisory.cve,
                    "severity": f.advisory.severity,
                    "cvss": f.advisory.cvss,
                    "summary": f.advisory.summary,
                    "fixed_version": f.advisory.fixed_version,
                    "reachable": f.reachable,
                    "reach_reason": f.reach_reason,
                    "rank": f.rank,
                }
                for f in findings
            ],
        }
        print(json.dumps(payload, indent=2))  # noqa: T201
        return 1 if findings else 0

    # Terminal output
    console.print(f"[bold cyan]Scanned {len(packages)} packages from composer.lock[/bold cyan]\n")

    if not findings:
        console.print("[bold green]No vulnerable dependencies detected.[/bold green]")
        return 0

    table = Table(title="Dependency Vulnerabilities", title_justify="left", show_header=True)
    table.add_column("Package", style="bold", no_wrap=True)
    table.add_column("Installed")
    table.add_column("Fixed In")
    table.add_column("Severity")
    table.add_column("Advisory", no_wrap=True)
    table.add_column("Reachability")

    for f in findings:
        sev_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
        }.get(f.advisory.severity, "white")

        reach_style = "bold green" if f.reachable else "dim"
        reach_badge = f"[{reach_style}]{'REACHABLE' if f.reachable else 'UNCALLED'}[/{reach_style}]"
        adv_label = f.advisory.cve or f.advisory.id

        table.add_row(
            f.package.name,
            f.package.version,
            f.advisory.fixed_version or "None",
            f"[{sev_color}]{f.advisory.severity.upper()}[/{sev_color}]",
            adv_label,
            f"{reach_badge}\n[dim]{f.reach_reason}[/dim]",
        )

    console.print(table)
    suffix = "issue" if len(findings) == 1 else "issues"
    console.print(f"\n[bold red]Found {len(findings)} vulnerable dependency {suffix}.[/bold red]")
    return 1


__all__ = [
    "Advisory",
    "DependencyFinding",
    "Package",
    "check_reachability",
    "generate_cyclonedx_sbom",
    "generate_spdx_sbom",
    "load_advisories",
    "matches_constraint",
    "parse_lockfile",
    "run_deps",
    "scan_dependencies",
]
