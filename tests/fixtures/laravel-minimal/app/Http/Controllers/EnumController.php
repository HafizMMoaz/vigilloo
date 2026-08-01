<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/EnumController.php
//
// Calls into an enum's static methods, where the sinks live. Before enum
// declarations were extracted the enum did not exist as far as the symbol table
// was concerned, so these calls resolved to nothing, the walk stopped at the
// call site, and the sink inside the enum was never reached.
//
// The stop was not even counted. An unresolved call into a class the project
// contains is exactly what the resolution rate is meant to measure, and a call
// into a type the extractor never created could not be told apart from a call
// into the framework, which is deliberately not counted.

namespace App\Http\Controllers;

use App\Enums\ReportFormat;
use Illuminate\Http\Request;

class EnumController
{
    // Positive: the sink is inside ReportFormat::purge, so this finding requires
    // the enum to have been extracted, the static call resolved to it, and the
    // body walked. The propagator step has to name the enum method.
    public function purge(Request $request)
    {
        ReportFormat::purge($request->input('table'));
    }

    // Negative: the enum method it reaches parameterises its query. Now that the
    // walk enters an enum body, the ordinary argument-precision rules have to
    // hold in there too.
    public function status(Request $request)
    {
        return ReportFormat::forStatus($request->input('status'));
    }
}
