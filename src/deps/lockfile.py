"""Parser for composer.lock dependency files."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Package:
    """Installed package specification from composer.lock."""

    name: str
    version: str
    raw_version: str
    is_dev: bool
    license: str | None = None
    description: str | None = None
    namespaces: tuple[str, ...] = ()


def _extract_namespaces(pkg_data: dict[str, Any]) -> tuple[str, ...]:
    namespaces: list[str] = []
    autoload = pkg_data.get("autoload", {})
    if isinstance(autoload, dict):
        for key in ("psr-4", "psr-0"):
            mapping = autoload.get(key)
            if isinstance(mapping, dict):
                for ns in mapping:
                    if isinstance(ns, str) and ns:
                        namespaces.append(ns.rstrip("\\"))
    return tuple(sorted(set(namespaces)))


def _extract_license(pkg_data: dict[str, Any]) -> str | None:
    lic = pkg_data.get("license")
    if isinstance(lic, list) and lic:
        return ", ".join(str(item) for item in lic if item)
    if isinstance(lic, str) and lic:
        return lic
    return None


def parse_lockfile(lockfile_path: Path) -> list[Package]:
    """Parse a composer.lock file and return all installed packages."""
    if not lockfile_path.exists():
        raise FileNotFoundError(f"composer.lock not found at: {lockfile_path}")

    content = lockfile_path.read_text(encoding="utf-8")
    data = json.loads(content)

    packages: list[Package] = []

    def _process_list(raw_list: Any, is_dev: bool) -> None:
        if not isinstance(raw_list, list):
            return
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            raw_version = item.get("version")
            if not isinstance(name, str) or not isinstance(raw_version, str):
                continue

            clean_version = raw_version.lstrip("vV").strip()
            desc = item.get("description")
            if not isinstance(desc, str):
                desc = None

            pkg = Package(
                name=name.lower(),
                version=clean_version,
                raw_version=raw_version,
                is_dev=is_dev,
                license=_extract_license(item),
                description=desc,
                namespaces=_extract_namespaces(item),
            )
            packages.append(pkg)

    _process_list(data.get("packages"), is_dev=False)
    _process_list(data.get("packages-dev"), is_dev=True)

    packages.sort(key=lambda p: (p.name, p.version))
    return packages
