"""Tests for CycloneDX and SPDX SBOM generation."""

import json

from vigilloo.deps.advisories import Advisory
from vigilloo.deps.lockfile import Package
from vigilloo.deps.reachability import ReachabilityResult
from vigilloo.deps.sbom import generate_cyclonedx_sbom, generate_spdx_sbom


def test_cyclonedx_sbom_generation() -> None:
    pkg = Package(
        name="guzzlehttp/guzzle",
        version="7.4.4",
        raw_version="7.4.4",
        is_dev=False,
        license="MIT",
        description="Guzzle HTTP client",
    )
    adv = Advisory(
        id="GHSA-c24v-8rfc-w8vw",
        cve="CVE-2022-31090",
        package_name="guzzlehttp/guzzle",
        affected_range="<7.4.5",
        fixed_version="7.4.5",
        severity="high",
        cvss=7.5,
        cwe="CWE-200",
        summary="CURLOPT_HTTPAUTH bypass",
    )
    reach = ReachabilityResult(reachable=True, reason="Reachable from route", rank=3)

    matched = {"guzzlehttp/guzzle": [(adv, reach)]}

    sbom_json = generate_cyclonedx_sbom("my-test-app", [pkg], matched)
    data = json.loads(sbom_json)

    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.5"
    assert data["metadata"]["component"]["name"] == "my-test-app"

    # Components
    assert len(data["components"]) == 1
    c = data["components"][0]
    assert c["name"] == "guzzlehttp/guzzle"
    assert c["version"] == "7.4.4"
    assert c["purl"] == "pkg:composer/guzzlehttp/guzzle@7.4.4"

    # Vulnerabilities
    assert len(data["vulnerabilities"]) == 1
    v = data["vulnerabilities"][0]
    assert v["id"] == "GHSA-c24v-8rfc-w8vw"
    assert v["ratings"][0]["severity"] == "high"


def test_spdx_sbom_generation() -> None:
    pkg = Package(
        name="guzzlehttp/guzzle",
        version="7.4.4",
        raw_version="7.4.4",
        is_dev=False,
        license="MIT",
    )
    sbom_json = generate_spdx_sbom("my-test-app", [pkg])
    data = json.loads(sbom_json)

    assert data["spdxVersion"] == "SPDX-2.3"
    assert data["name"] == "my-test-app"
    assert len(data["packages"]) == 1
    p = data["packages"][0]
    assert p["name"] == "guzzlehttp/guzzle"
    assert p["versionInfo"] == "7.4.4"
