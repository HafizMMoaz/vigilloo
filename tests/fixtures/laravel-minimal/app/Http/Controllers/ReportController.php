<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/ReportController.php
//
// Routes into ReportRepository, so the DB facade sinks are reached the way a
// real one would be: from an HTTP entry point, through the call graph. A sink
// no route reaches is not a finding here, by design.

namespace App\Http\Controllers;

use App\Repositories\ReportRepository;
use Illuminate\Http\Request;

class ReportController
{
    public function __construct(private ReportRepository $reports)
    {
    }

    public function byStatus(Request $request)
    {
        return $this->reports->byStatus($request->input('status'));
    }

    public function totals(Request $request)
    {
        return $this->reports->totalExpression($request->input('column'));
    }

    public function purge(Request $request)
    {
        return $this->reports->purge($request->input('table'));
    }

    public function bound(Request $request)
    {
        return $this->reports->bound($request->input('status'));
    }

    public function columns(Request $request)
    {
        return $this->reports->columns();
    }
}
