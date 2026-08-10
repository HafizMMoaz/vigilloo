from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project


def test_blade_foreach_loop_taint(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class ItemController {
    public function index(Request $request) {
        $items = [$request->input('q')];
        return view('items.index', ['items' => $items]);
    }
}
"""
    template_code = """<div>
    @foreach($items as $item)
        {!! $item !!}
    @endforeach
</div>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\ItemController;

Route::get('/items', [ItemController::class, 'index']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views/items").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/ItemController.php").write_text(controller_code)
    (tmp_path / "resources/views/items/index.blade.php").write_text(template_code)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "php.xss"]
    assert len(xss_findings) == 1
    path = xss_findings[0].evidence_path
    assert path[0].role == "entry"
    assert path[1].role == "source"
    assert path[-1].role == "sink"
    assert "{!! $item !!}" in path[-1].snippet


def test_blade_forelse_loop_taint(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class PostController {
    public function list(Request $request) {
        $posts = [$request->input('tag')];
        return view('posts.list', ['posts' => $posts]);
    }
}
"""
    template_code = """<div>
    @forelse($posts as $idx => $post)
        <div>{!! $post !!}</div>
    @empty
        <p>No posts</p>
    @endforelse
</div>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\PostController;

Route::get('/posts', [PostController::class, 'list']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views/posts").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/PostController.php").write_text(controller_code)
    (tmp_path / "resources/views/posts/list.blade.php").write_text(template_code)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "php.xss"]
    assert len(xss_findings) == 1
    assert "{!! $post !!}" in xss_findings[0].evidence_path[-1].snippet


def test_blade_foreach_escaped_negative(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class SafeLoopController {
    public function show(Request $request) {
        $items = [$request->input('q')];
        return view('safe_loop', ['items' => $items]);
    }
}
"""
    template_code = """<div>
    @foreach($items as $item)
        {{ $item }}
    @endforeach
</div>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\SafeLoopController;

Route::get('/safe-loop', [SafeLoopController::class, 'show']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/SafeLoopController.php").write_text(controller_code)
    (tmp_path / "resources/views/safe_loop.blade.php").write_text(template_code)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "php.xss"]
    assert len(xss_findings) == 0
