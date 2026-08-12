from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import LDAP_INJECTION, LOG_INJECTION, XPATH_INJECTION
from vigilloo.taint import find_taint_paths


def _minimal_project(tmp_path: Path, view_body: str) -> Path:
    (tmp_path / "routes").mkdir()
    (tmp_path / "app" / "Http" / "Controllers").mkdir(parents=True)

    (tmp_path / "routes" / "web.php").write_text(
        "<?php\n"
        "use App\\Http\\Controllers\\MyController;\n"
        "use Illuminate\\Support\\Facades\\Route;\n"
        "Route::post('/test', [MyController::class, 'act']);\n"
    )
    (tmp_path / "app" / "Http" / "Controllers" / "MyController.php").write_text(
        "<?php\n"
        "namespace App\\Http\\Controllers;\n"
        "use Illuminate\\Http\\Request;\n"
        "use Illuminate\\Support\\Facades\\Log;\n"
        "class MyController\n"
        "{\n"
        f"{view_body}\n"
        "}\n"
    )

    return tmp_path


def test_positive_ldap_injection(tmp_path: Path):
    body = """
        public function act(Request $request) {
            ldap_search($link, 'ou=users,dc=example,dc=com', $request->input('filter'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == LDAP_INJECTION.id


def test_positive_xpath_injection(tmp_path: Path):
    body = """
        public function act(Request $request) {
            $xpath = new \\DOMXPath($doc);
            $xpath->query("//user[name='" . $request->input('name') . "']");
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == XPATH_INJECTION.id


def test_positive_log_injection_facade(tmp_path: Path):
    body = """
        public function act(Request $request) {
            Log::info("User accessed: " . $request->input('path'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == LOG_INJECTION.id


def test_positive_log_injection_helper(tmp_path: Path):
    body = """
        public function act(Request $request) {
            logger("User accessed: " . $request->input('path'));
        }
    """
    proj_dir = _minimal_project(tmp_path, body)
    proj = load_project(proj_dir)
    paths = find_taint_paths(proj)
    assert len(paths) == 1
    assert paths[0][-1].rule_id == LOG_INJECTION.id
