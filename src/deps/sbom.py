"""Software Bill of Materials (SBOM) generation (CycloneDX and SPDX)."""

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .. import __version__
from .advisories import Advisory
from .lockfile import Package

if TYPE_CHECKING:
    from .reachability import ReachabilityResult


def generate_cyclonedx_sbom(
    project_name: str,
    packages: list[Package],
    matched_advisories: dict[str, list[tuple[Advisory, "ReachabilityResult"]]],
) -> str:
    """Generate a CycloneDX 1.5 JSON SBOM representation."""
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_serial = f"urn:uuid:{uuid.uuid4()}"

    components: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []

    for pkg in packages:
        purl = f"pkg:composer/{pkg.name}@{pkg.version}"
        comp: dict[str, Any] = {
            "type": "library",
            "name": pkg.name,
            "version": pkg.version,
            "purl": purl,
            "scope": "excluded" if pkg.is_dev else "required",
        }
        if pkg.description:
            comp["description"] = pkg.description
        if pkg.license:
            comp["licenses"] = [{"license": {"id": pkg.license}}]

        components.append(comp)

        # Append vulnerabilities affecting this component
        advisories = matched_advisories.get(pkg.name, [])
        for adv, reach in advisories:
            vuln_entry: dict[str, Any] = {
                "id": adv.id,
                "source": {"name": "Vigilloo Advisory DB"},
                "description": adv.summary,
                "ratings": [
                    {
                        "severity": adv.severity.lower(),
                        "score": adv.cvss if adv.cvss is not None else 0.0,
                    }
                ],
                "affects": [{"ref": purl}],
                "properties": [
                    {"name": "vigilloo:reachable", "value": str(reach.reachable).lower()},
                    {"name": "vigilloo:reach_reason", "value": reach.reason},
                ],
            }
            if adv.cve:
                vuln_entry["references"] = [{"id": adv.cve, "source": {"name": "NVD"}}]
            if adv.cwe and adv.cwe.startswith("CWE-"):
                vuln_entry["cwes"] = [int(adv.cwe.replace("CWE-", ""))]

            vulnerabilities.append(vuln_entry)

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": [
                {
                    "vendor": "Vigilloo",
                    "name": "vigilloo",
                    "version": __version__,
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
            },
        },
        "components": components,
    }
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities

    return json.dumps(doc, indent=2) + "\n"


def generate_spdx_sbom(
    project_name: str,
    packages: list[Package],
) -> str:
    """Generate an SPDX 2.3 JSON SBOM representation."""
    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_namespace = f"http://spdx.org/spdxdocs/{project_name}-{uuid.uuid4()}"

    spdx_packages: list[dict[str, Any]] = []
    for pkg in packages:
        spdx_packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{pkg.name.replace('/', '-')}",
                "name": pkg.name,
                "versionInfo": pkg.version,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": pkg.license or "NOASSERTION",
                "licenseDeclared": pkg.license or "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:composer/{pkg.name}@{pkg.version}",
                    }
                ],
            }
        )

    doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": project_name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "creators": [f"Tool: vigilloo-{__version__}"],
            "created": now_iso,
        },
        "packages": spdx_packages,
    }
    return json.dumps(doc, indent=2) + "\n"
