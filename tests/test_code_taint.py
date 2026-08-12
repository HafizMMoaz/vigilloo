"""Tests for code kind and code execution sinks (TASK-053, CWE-94/CWE-502)."""

import pytest

from vigilloo.graph import load_project
from vigilloo.laravel.vocabulary import CODE_EXECUTION_RULE
from vigilloo.taint import find_taint_paths


@pytest.fixture
def code_project(tmp_path):
    """A project with a controller exercising every code execution sink variant."""
    controller = tmp_path / "app" / "Http" / "Controllers" / "CodeController.php"
    controller.parent.mkdir(parents=True, exist_ok=True)
    controller.write_text(
        """<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;

class CodeController
{
    public function vulnerableEval(Request $request)
    {
        $code = $request->input('code');
        eval($code);
    }

    public function vulnerableAssert(Request $request)
    {
        $expr = $request->input('expr');
        assert($expr);
    }

    public function vulnerableCreateFunction(Request $request)
    {
        $body = $request->input('body');
        $fn = create_function('$x', $body);
    }

    public function vulnerableUnserialize(Request $request)
    {
        $data = $request->input('data');
        unserialize($data);
    }

    public function vulnerableInclude(Request $request)
    {
        $path = $request->input('path');
        include $path;
    }

    public function vulnerableRequire(Request $request)
    {
        $path = $request->input('path');
        require $path;
    }

    public function vulnerableCallUserFunc(Request $request)
    {
        $cb = $request->input('cb');
        call_user_func($cb);
    }

    public function safeEval(Request $request)
    {
        // Constant string - not tainted.
        $result = eval('return 1 + 1;');
    }

    public function safeInclude(Request $request)
    {
        // Allowlisted path - not tainted.
        include 'views/home.blade.php';
    }
}
"""
    )

    routes = tmp_path / "routes" / "web.php"
    routes.parent.mkdir(parents=True, exist_ok=True)
    routes.write_text(
        """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\CodeController;

Route::post('/eval', [CodeController::class, 'vulnerableEval']);
Route::post('/assert', [CodeController::class, 'vulnerableAssert']);
Route::post('/create-function',
    [CodeController::class, 'vulnerableCreateFunction']);
Route::post('/unserialize', [CodeController::class, 'vulnerableUnserialize']);
Route::post('/include', [CodeController::class, 'vulnerableInclude']);
Route::post('/require', [CodeController::class, 'vulnerableRequire']);
Route::post('/call-user-func', [CodeController::class, 'vulnerableCallUserFunc']);
Route::get('/safe-eval', [CodeController::class, 'safeEval']);
Route::get('/safe-include', [CodeController::class, 'safeInclude']);
"""
    )

    return load_project(tmp_path)


def test_vulnerable_code_sinks_fire_code_execution(code_project):
    paths = find_taint_paths(code_project)
    code_paths = [p for p in paths if p[-1].rule_id == CODE_EXECUTION_RULE]

    # Should detect eval, assert, create_function, unserialize, include,
    # require, call_user_func - 7 paths
    assert len(code_paths) == 7

    urls = {p[0].snippet for p in code_paths}
    assert any("/eval" in s for s in urls)
    assert any("/assert" in s for s in urls)
    assert any("/create-function" in s for s in urls)
    assert any("/unserialize" in s for s in urls)
    assert any("/include" in s for s in urls)
    assert any("/require" in s for s in urls)
    assert any("/call-user-func" in s for s in urls)


def test_safe_eval_does_not_fire(code_project):
    paths = find_taint_paths(code_project)
    safe_eval_paths = [
        p for p in paths if "/safe-eval" in p[0].snippet and p[-1].rule_id == CODE_EXECUTION_RULE
    ]
    assert len(safe_eval_paths) == 0


def test_safe_include_does_not_fire(code_project):
    paths = find_taint_paths(code_project)
    safe_include_paths = [
        p for p in paths if "/safe-include" in p[0].snippet and p[-1].rule_id == CODE_EXECUTION_RULE
    ]
    assert len(safe_include_paths) == 0


def test_no_sanitizer_clears_code_kind():
    """TaintKind.CODE has no sanitizer - this is an invariant of the design.

    There is no function call that makes untrusted data safe to pass to eval().
    The spec explicitly states 'nothing clears this kind' and the SANITIZERS
    table must not contain a CODE entry, now or ever.
    """
    from vigilloo.laravel.vocabulary import SANITIZERS, TaintKind

    assert TaintKind.CODE not in {k for kinds in SANITIZERS.values() for k in kinds}
    # Verify sanitizer_clears never returns CODE.
    from vigilloo.laravel.vocabulary import sanitizer_clears

    for name in SANITIZERS:
        assert TaintKind.CODE not in sanitizer_clears(name), (
            f"sanitizer '{name}' must not clear CODE kind"
        )
