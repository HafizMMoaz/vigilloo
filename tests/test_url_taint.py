import pytest

from vigilloo.graph import load_project
from vigilloo.laravel.vocabulary import SSRF_RULE
from vigilloo.taint import find_taint_paths

@pytest.fixture
def ssrf_project(tmp_path):
    """A project with a controller exercising every SSRF sink variant."""
    controller = tmp_path / "app" / "Http" / "Controllers" / "SsrfController.php"
    controller.parent.mkdir(parents=True, exist_ok=True)
    controller.write_text(
        """<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\Http;
use GuzzleHttp\\Client;

class SsrfController
{
    public function vulnerableHttpGet(Request $request)
    {
        $url = $request->input('url');
        Http::get($url);
    }

    public function vulnerableGuzzleClient(Request $request)
    {
        $url = $request->input('url');
        $client = new Client();
        $client->post($url);
    }

    public function vulnerableCurlSetopt(Request $request)
    {
        $url = $request->input('url');
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_exec($ch);
    }

    public function safeCurlSetoptOtherOption(Request $request)
    {
        $timeout = $request->input('timeout');
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_exec($ch);
    }

    public function vulnerableFileGetContents(Request $request)
    {
        $url = $request->input('url');
        file_get_contents($url);
    }

    public function safeUrlencodeSanitizer(Request $request)
    {
        $url = $request->input('url');
        $safe = urlencode($url);
        Http::get("https://example.com/?q=" . $safe);
    }
}
"""
    )

    routes = tmp_path / "routes" / "web.php"
    routes.parent.mkdir(parents=True, exist_ok=True)
    routes.write_text(
        """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\SsrfController;

Route::post('/http-get', [SsrfController::class, 'vulnerableHttpGet']);
Route::post('/guzzle', [SsrfController::class, 'vulnerableGuzzleClient']);
Route::post('/curl-setopt', [SsrfController::class, 'vulnerableCurlSetopt']);
Route::post('/curl-safe', [SsrfController::class, 'safeCurlSetoptOtherOption']);
Route::post('/file-get-contents', [SsrfController::class, 'vulnerableFileGetContents']);
Route::post('/urlencode-safe', [SsrfController::class, 'safeUrlencodeSanitizer']);
"""
    )
    return load_project(tmp_path)

def test_ssrf_sinks_are_found(ssrf_project):
    paths = find_taint_paths(ssrf_project)

    findings = [
        path for path in paths
        if path[-1].rule_id == SSRF_RULE
    ]

    # file_get_contents is also a path traversal sink
    path_traversal_findings = [
        path for path in paths
        if path[-1].rule_id == "php.path-traversal" and "file_get_contents" in path[-1].snippet
    ]

    snippets = {path[-1].snippet for path in findings}
    
    
    assert "Http::get($url)" in snippets
    assert "$client->post($url)" in snippets
    assert "curl_setopt($ch, CURLOPT_URL, $url)" in snippets
    assert "file_get_contents($url)" in snippets
    
    # Safe cases should not be found
    assert not any("CURLOPT_TIMEOUT" in snippet for snippet in snippets)
    assert not any("urlencode" in snippet for snippet in snippets)
    
    # Check that file_get_contents produces BOTH path-traversal and SSRF
    assert len(path_traversal_findings) == 1
    assert path_traversal_findings[0][-1].snippet == "file_get_contents($url)"
