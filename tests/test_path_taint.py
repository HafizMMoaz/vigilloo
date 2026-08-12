"""Tests for path kind and path traversal sinks (TASK-054, CWE-22/CWE-434)."""

import pytest

from vigilloo.graph import load_project
from vigilloo.laravel.vocabulary import PATH_TRAVERSAL_RULE
from vigilloo.taint import find_taint_paths


@pytest.fixture
def path_project(tmp_path):
    """A project with a controller exercising every path traversal sink variant."""
    controller = tmp_path / "app" / "Http" / "Controllers" / "PathController.php"
    controller.parent.mkdir(parents=True, exist_ok=True)
    controller.write_text(
        """<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\Storage;

class PathController
{
    public function vulnerableFileGetContents(Request $request)
    {
        $path = $request->input('path');
        file_get_contents($path);
    }

    public function vulnerableFilePutContents(Request $request)
    {
        $path = $request->input('path');
        file_put_contents($path, 'data');
    }

    public function vulnerableFopen(Request $request)
    {
        $path = $request->input('path');
        fopen($path, 'r');
    }

    public function vulnerableUnlink(Request $request)
    {
        $path = $request->input('path');
        unlink($path);
    }

    public function vulnerableCopy(Request $request)
    {
        $path = $request->input('path');
        copy($path, 'dest');
    }

    public function vulnerableRename(Request $request)
    {
        $path = $request->input('path');
        rename($path, 'dest');
    }

    public function vulnerableStorageGet(Request $request)
    {
        $path = $request->input('path');
        Storage::get($path);
    }

    public function vulnerableStoragePut(Request $request)
    {
        $path = $request->input('path');
        Storage::put($path, 'data');
    }

    public function vulnerableStorageDelete(Request $request)
    {
        $path = $request->input('path');
        Storage::delete($path);
    }

    public function vulnerableStorageDisk(Request $request)
    {
        $disk = $request->input('disk');
        Storage::disk($disk)->get('file.txt');
    }

    public function safeBasename(Request $request)
    {
        $path = $request->input('path');
        $safe_path = basename($path);
        file_get_contents('/var/www/uploads/' . $safe_path);
    }

    public function safeIntval(Request $request)
    {
        $id = $request->input('id');
        $safe_id = intval($id);
        Storage::get('users/' . $safe_id . '/profile.jpg');
    }
}
"""
    )

    routes = tmp_path / "routes" / "web.php"
    routes.parent.mkdir(parents=True, exist_ok=True)
    routes.write_text(
        """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\PathController;

Route::post('/file-get-contents', [PathController::class, 'vulnerableFileGetContents']);
Route::post('/file-put-contents', [PathController::class, 'vulnerableFilePutContents']);
Route::post('/fopen', [PathController::class, 'vulnerableFopen']);
Route::post('/unlink', [PathController::class, 'vulnerableUnlink']);
Route::post('/copy', [PathController::class, 'vulnerableCopy']);
Route::post('/rename', [PathController::class, 'vulnerableRename']);
Route::post('/storage-get', [PathController::class, 'vulnerableStorageGet']);
Route::post('/storage-put', [PathController::class, 'vulnerableStoragePut']);
Route::post('/storage-delete', [PathController::class, 'vulnerableStorageDelete']);
Route::post('/storage-disk', [PathController::class, 'vulnerableStorageDisk']);

Route::post('/safe-basename', [PathController::class, 'safeBasename']);
Route::post('/safe-intval', [PathController::class, 'safeIntval']);
"""
    )

    return load_project(tmp_path)


def test_vulnerable_path_sinks_fire_path_traversal(path_project):
    paths = find_taint_paths(path_project)
    path_paths = [p for p in paths if p[-1].rule_id == PATH_TRAVERSAL_RULE]

    # Should detect all 10 vulnerable sinks
    assert len(path_paths) == 10

    urls = {p[0].snippet for p in path_paths}
    assert any("/file-get-contents" in s for s in urls)
    assert any("/file-put-contents" in s for s in urls)
    assert any("/fopen" in s for s in urls)
    assert any("/unlink" in s for s in urls)
    assert any("/copy" in s for s in urls)
    assert any("/rename" in s for s in urls)
    assert any("/storage-get" in s for s in urls)
    assert any("/storage-put" in s for s in urls)
    assert any("/storage-delete" in s for s in urls)
    assert any("/storage-disk" in s for s in urls)


def test_safe_basename_does_not_fire(path_project):
    paths = find_taint_paths(path_project)
    safe_paths = [
        p
        for p in paths
        if "/safe-basename" in p[0].snippet and p[-1].rule_id == PATH_TRAVERSAL_RULE
    ]
    assert len(safe_paths) == 0


def test_safe_intval_does_not_fire(path_project):
    paths = find_taint_paths(path_project)
    safe_paths = [
        p for p in paths if "/safe-intval" in p[0].snippet and p[-1].rule_id == PATH_TRAVERSAL_RULE
    ]
    assert len(safe_paths) == 0
