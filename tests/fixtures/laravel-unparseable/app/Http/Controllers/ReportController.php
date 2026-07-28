<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

// This file does not parse, and that is the point of it. The parameter list
// below is never closed and the view() call is never terminated, so
// tree-sitter reports an error node and the scan records the file as only
// partially analysed. Do not fix the syntax: the coverage rate this fixture
// measures is 100% without it, and the test that guards invariant 4 would
// then pass no matter what the engine counted.
class ReportController
{
    public function index(Request $request
    {
        return view('reports.index'
    }
}
