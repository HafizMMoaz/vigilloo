from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.rules import scan_project


def test_blade_include_chain_taint(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class PageController {
    public function show(Request $request) {
        $msg = $request->input('msg');
        return view('pages.show', ['msg' => $msg]);
    }
}
"""
    parent_template = """<div>
    @include('partials.header', ['title' => $msg])
</div>
"""
    header_template = """<header>
    {!! $title !!}
</header>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\PageController;

Route::get('/show', [PageController::class, 'show']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views/pages").mkdir(parents=True)
    (tmp_path / "resources/views/partials").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/PageController.php").write_text(controller_code)
    (tmp_path / "resources/views/pages/show.blade.php").write_text(parent_template)
    (tmp_path / "resources/views/partials/header.blade.php").write_text(header_template)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "laravel.blade-raw-echo"]
    assert len(xss_findings) == 1
    path = xss_findings[0].evidence_path
    assert path[0].role == "entry"
    assert path[1].role == "source"
    assert path[-1].role == "sink"
    assert "{!! $title !!}" in path[-1].snippet


def test_blade_inheritance_taint(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class ArticleController {
    public function show(Request $request) {
        $title = $request->input('title');
        return view('articles.show', ['title' => $title]);
    }
}
"""
    child_template = """@extends('layouts.app')
@section('content')
<p>Article Body</p>
@endsection
"""
    layout_template = """<!DOCTYPE html>
<html>
<head>
    <title>{!! $title !!}</title>
</head>
<body>
    @yield('content')
</body>
</html>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\ArticleController;

Route::get('/article', [ArticleController::class, 'show']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views/articles").mkdir(parents=True)
    (tmp_path / "resources/views/layouts").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/ArticleController.php").write_text(controller_code)
    (tmp_path / "resources/views/articles/show.blade.php").write_text(child_template)
    (tmp_path / "resources/views/layouts/app.blade.php").write_text(layout_template)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "laravel.blade-raw-echo"]
    assert len(xss_findings) == 1
    assert "{!! $title !!}" in xss_findings[0].evidence_path[-1].snippet


def test_blade_component_tag_taint(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class AlertController {
    public function show(Request $request) {
        $userMsg = $request->input('msg');
        return view('alert_page', ['userMsg' => $userMsg]);
    }
}
"""
    page_template = """<div>
    <x-alert :message="$userMsg" type="warning" />
</div>
"""
    component_template = """<div class="alert alert-{{ $type }}">
    {!! $message !!}
</div>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\AlertController;

Route::get('/alert', [AlertController::class, 'show']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views/components").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/AlertController.php").write_text(controller_code)
    (tmp_path / "resources/views/alert_page.blade.php").write_text(page_template)
    (tmp_path / "resources/views/components/alert.blade.php").write_text(component_template)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "laravel.blade-raw-echo"]
    assert len(xss_findings) == 1
    assert "{!! $message !!}" in xss_findings[0].evidence_path[-1].snippet


def test_blade_include_escaped_echo_negative(tmp_path: Path) -> None:
    controller_code = """<?php
namespace App\\Http\\Controllers;

use Illuminate\\Http\\Request;

class SafeController {
    public function show(Request $request) {
        $msg = $request->input('msg');
        return view('safe_page', ['msg' => $msg]);
    }
}
"""
    parent_template = """<div>
    @include('partials.safe_header', ['title' => $msg])
</div>
"""
    header_template = """<header>
    {{ $title }}
</header>
"""
    routes_code = """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\SafeController;

Route::get('/safe', [SafeController::class, 'show']);
"""

    (tmp_path / "app/Http/Controllers").mkdir(parents=True)
    (tmp_path / "resources/views/partials").mkdir(parents=True)
    (tmp_path / "routes").mkdir(parents=True)

    (tmp_path / "app/Http/Controllers/SafeController.php").write_text(controller_code)
    (tmp_path / "resources/views/safe_page.blade.php").write_text(parent_template)
    (tmp_path / "resources/views/partials/safe_header.blade.php").write_text(header_template)
    (tmp_path / "routes/web.php").write_text(routes_code)

    project = load_project(tmp_path)
    findings = scan_project(project)

    xss_findings = [f for f in findings if f.rule_id == "laravel.blade-raw-echo"]
    assert len(xss_findings) == 0
