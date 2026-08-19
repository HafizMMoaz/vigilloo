<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/NullsafeController.php
//
// The nullsafe operator, named in docs/03-parser section "PHP features that
// must be handled correctly". `$request?->input('sort')` reads exactly what
// `$request->input('sort')` reads - the operator decides what happens when the
// receiver is null, and says nothing about where the value came from.
//
// tree-sitter spells the two forms as different node types, so a walk that
// matches member_call_expression by name sees the arrow form and is blind to
// the nullsafe one. That is a silent false negative: the code is a textbook
// injection and the scan reports nothing.

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class NullsafeController
{
    // Positive: the nullsafe form of the source method call.
    public function sort(Request $request)
    {
        return DB::raw('select * from orders order by ' . $request?->input('sort'));
    }

    // Positive: the nullsafe form of the magic property read. Two node types are
    // involved rather than one, and a fix to the call form alone would miss this.
    public function magic(Request $request)
    {
        return DB::raw('select * from orders order by ' . $request?->column);
    }

    // Positive: assigned before use, so the source step lands on the assignment.
    public function assigned(Request $request)
    {
        $column = $request?->input('column');

        return DB::raw("select * from orders order by {$column}");
    }

    // Negative: nullsafe on an ordinary object. The receiver is what makes a read
    // a source, and the operator does not change the receiver. Without this the
    // fix degrades into "every ?-> is tainted", which is most of a modern codebase.
    public function ordinary(Invoice $invoice)
    {
        return DB::table('pages')->orderByRaw($invoice?->column);
    }

    // Negative: sanitized after a nullsafe read. Pins that a nullsafe source is an
    // ordinary tainted value rather than a special case that skips the sanitizer.
    public function escaped(Request $request)
    {
        return DB::table('orders')->orderByRaw(intval($request?->input('column')));
    }
}
