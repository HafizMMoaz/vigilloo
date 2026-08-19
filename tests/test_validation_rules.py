from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.laravel.validation import parse_rules_array, rule_clears
from vigilloo.models import ALL_KINDS, TaintKind
from vigilloo.parser import find_all, parse_source
from vigilloo.rules import scan_project


def test_rule_clears_mappings() -> None:
    assert rule_clears("integer") == frozenset({TaintKind.SQL})
    assert rule_clears("numeric") == frozenset({TaintKind.SQL})
    assert rule_clears("exists:users,id") == frozenset({TaintKind.SQL})
    assert rule_clears("in:admin,user") == ALL_KINDS
    assert rule_clears("string") == frozenset()
    assert rule_clears("required") == frozenset()


def test_parse_rules_array() -> None:
    code = b"""<?php
    $rules = [
        'id' => 'required|integer',
        'role' => ['required', 'in:admin,user'],
        'name' => 'required|string',
    ];
    """
    parsed = parse_source(Path("app/Http/Controllers/TestController.php"), code)
    array_node = find_all(parsed.tree.root_node, "array_creation_expression")[0]

    cleared = parse_rules_array(array_node, code)
    assert cleared["id"] == frozenset({TaintKind.SQL})
    assert cleared["role"] == ALL_KINDS
    assert cleared["name"] == frozenset()


def test_validation_rule_taint_clearing_integration(tmp_path: Path) -> None:
    """Acceptance test: validate(['id' => 'integer']) then whereRaw with $id does not fire.

    Validation with 'string' rule still fires whereRaw SQL injection.
    """
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;

class UserController {
    public function safeSql(Request $request) {
        $request->validate(['id' => 'integer']);
        $id = $request->input('id');
        DB::whereRaw("id = $id");
    }

    public function unsafeString(Request $request) {
        $request->validate(['id' => 'string']);
        $id = $request->input('id');
        DB::whereRaw("id = $id");
    }

    public function safeIn(Request $request) {
        $request->validate(['role' => 'in:admin,user']);
        $role = $request->input('role');
        DB::whereRaw("role = '$role'");
    }
}
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\UserController;

Route::get('/safe-sql', [UserController::class, 'safeSql']);
Route::get('/unsafe-string', [UserController::class, 'unsafeString']);
Route::get('/safe-in', [UserController::class, 'safeIn']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)
    (tmp_path / "app/Http/Controllers/UserController.php").write_text(controller_code)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    # safeSql: whereRaw on line 11 with integer-validated $id does NOT fire SQL injection
    sql_findings_safe = [
        f for f in findings if f.rule_id == "laravel.raw-query" and f.span.start_line == 11
    ]
    assert len(sql_findings_safe) == 0

    # unsafeString: whereRaw on line 17 with string-validated $id DOES fire SQL injection
    sql_findings_unsafe = [
        f for f in findings if f.rule_id == "laravel.raw-query" and f.span.start_line == 17
    ]
    assert len(sql_findings_unsafe) == 1

    # safeIn: whereRaw on line 23 with in:admin,user validated $role does NOT fire SQL injection
    sql_findings_in = [
        f for f in findings if f.rule_id == "laravel.raw-query" and f.span.start_line == 23
    ]
    assert len(sql_findings_in) == 0
