"""Tests for shell taint kind and command injection sinks (TASK-052)."""

import pytest

from vigilloo.graph import load_project
from vigilloo.laravel.vocabulary import COMMAND_INJECTION_RULE, XSS_RULE
from vigilloo.taint import find_taint_paths


@pytest.fixture
def shell_project(tmp_path):
    controller = tmp_path / "app" / "Http" / "Controllers" / "ShellController.php"
    controller.parent.mkdir(parents=True, exist_ok=True)
    controller.write_text(
        """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\Process;

class ShellController
{
    public function vulnerableExec(Request $request)
    {
        $cmd = $request->input('cmd');
        exec($cmd);
    }

    public function vulnerableShellExec(Request $request)
    {
        $cmd = $request->input('cmd');
        shell_exec($cmd);
    }

    public function vulnerableSystem(Request $request)
    {
        $cmd = $request->input('cmd');
        system($cmd);
    }

    public function vulnerableBackticks(Request $request)
    {
        $cmd = $request->input('cmd');
        `$cmd`;
    }

    public function vulnerableProcessString(Request $request)
    {
        $cmd = $request->input('cmd');
        Process::run($cmd);
    }

    public function safeProcessArray(Request $request)
    {
        $cmd = $request->input('cmd');
        Process::run(['ls', $cmd]);
    }

    public function safeEscapedShell(Request $request)
    {
        $cmd = $request->input('cmd');
        $safe = escapeshellarg($cmd);
        exec($safe);
    }

    public function escapedShellDoesNotClearHtml(Request $request)
    {
        $cmd = $request->input('cmd');
        $safe = escapeshellarg($cmd);
        return view('output.show', ['safe' => $safe]);
    }
}
"""
    )

    blade = tmp_path / "resources" / "views" / "output" / "show.blade.php"
    blade.parent.mkdir(parents=True, exist_ok=True)
    blade.write_text("<p>{!! $safe !!}</p>\n")

    routes = tmp_path / "routes" / "web.php"
    routes.parent.mkdir(parents=True, exist_ok=True)
    routes.write_text(
        """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\ShellController;

Route::get('/vulnerable-exec', [ShellController::class, 'vulnerableExec']);
Route::get('/vulnerable-shell-exec', [ShellController::class, 'vulnerableShellExec']);
Route::get('/vulnerable-system', [ShellController::class, 'vulnerableSystem']);
Route::get('/vulnerable-backticks', [ShellController::class, 'vulnerableBackticks']);
Route::get('/vulnerable-process-string', [ShellController::class, 'vulnerableProcessString']);
Route::get('/safe-process-array', [ShellController::class, 'safeProcessArray']);
Route::get('/safe-escaped-shell', [ShellController::class, 'safeEscapedShell']);
Route::get('/escaped-does-not-clear-html',
    [ShellController::class, 'escapedShellDoesNotClearHtml']);
"""
    )

    return load_project(tmp_path)


def test_vulnerable_shell_sinks_fire_command_injection(shell_project):
    paths = find_taint_paths(shell_project)
    command_injection_paths = [p for p in paths if p[-1].rule_id == COMMAND_INJECTION_RULE]

    # Should detect vulnerableExec, vulnerableShellExec, vulnerableSystem,
    # vulnerableBackticks, vulnerableProcessString
    assert len(command_injection_paths) == 5

    urls = {p[0].snippet for p in command_injection_paths}
    assert any("/vulnerable-exec" in s for s in urls)
    assert any("/vulnerable-shell-exec" in s for s in urls)
    assert any("/vulnerable-system" in s for s in urls)
    assert any("/vulnerable-backticks" in s for s in urls)
    assert any("/vulnerable-process-string" in s for s in urls)


def test_safe_process_array_form_does_not_fire(shell_project):
    paths = find_taint_paths(shell_project)
    safe_array_paths = [
        p
        for p in paths
        if "/safe-process-array" in p[0].snippet and p[-1].rule_id == COMMAND_INJECTION_RULE
    ]
    assert len(safe_array_paths) == 0


def test_escapeshellarg_clears_shell_taint(shell_project):
    paths = find_taint_paths(shell_project)
    escaped_shell_paths = [
        p
        for p in paths
        if "/safe-escaped-shell" in p[0].snippet and p[-1].rule_id == COMMAND_INJECTION_RULE
    ]
    assert len(escaped_shell_paths) == 0


def test_escapeshellarg_does_not_clear_html_taint(shell_project):
    paths = find_taint_paths(shell_project)
    html_paths = [
        p
        for p in paths
        if "/escaped-does-not-clear-html" in p[0].snippet and p[-1].rule_id == XSS_RULE
    ]
    assert len(html_paths) == 1
