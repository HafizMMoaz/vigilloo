"""Tests for dependency reachability ranking."""

from pathlib import Path

from vigilloo.deps.advisories import Advisory
from vigilloo.deps.lockfile import Package
from vigilloo.deps.reachability import check_reachability
from vigilloo.graph import load_project


def test_reachability_with_real_project(tmp_path: Path) -> None:
    # Build minimal project that imports GuzzleHttp\Client
    app_dir = tmp_path / "app" / "Http" / "Controllers"
    app_dir.mkdir(parents=True)
    controller = app_dir / "ApiController.php"
    controller.write_text(
        """<?php
namespace App\\Http\\Controllers;

use GuzzleHttp\\Client;

class ApiController {
    public function fetch() {
        $c = new Client();
        return $c;
    }
}
""",
        encoding="utf-8",
    )

    routes_dir = tmp_path / "routes"
    routes_dir.mkdir(parents=True)
    api_routes = routes_dir / "api.php"
    api_routes.write_text(
        """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\ApiController;

Route::get('/fetch', [ApiController::class, 'fetch']);
""",
        encoding="utf-8",
    )

    project = load_project(tmp_path)

    guzzle_pkg = Package(
        name="guzzlehttp/guzzle",
        version="7.4.4",
        raw_version="7.4.4",
        is_dev=False,
        namespaces=("GuzzleHttp",),
    )
    guzzle_adv = Advisory(
        id="GHSA-c24v-8rfc-w8vw",
        cve="CVE-2022-31090",
        package_name="guzzlehttp/guzzle",
        affected_range="<7.4.5",
        fixed_version="7.4.5",
        severity="high",
        summary="CURLOPT_HTTPAUTH bypass",
    )

    unrelated_pkg = Package(
        name="phpoffice/phpspreadsheet",
        version="1.28.0",
        raw_version="1.28.0",
        is_dev=False,
        namespaces=("PhpOffice\\PhpSpreadsheet",),
    )
    unrelated_adv = Advisory(
        id="GHSA-7955-v6wf-2cqw",
        package_name="phpoffice/phpspreadsheet",
        affected_range="<1.29.0",
        fixed_version="1.29.0",
        severity="high",
        summary="XXE injection",
    )

    guzzle_reach = check_reachability(guzzle_pkg, guzzle_adv, project)
    assert guzzle_reach.reachable is True
    assert guzzle_reach.rank >= 2

    unrelated_reach = check_reachability(unrelated_pkg, unrelated_adv, project)
    assert unrelated_reach.reachable is False
    assert unrelated_reach.rank == 1
    assert "Uncalled" in unrelated_reach.reason
