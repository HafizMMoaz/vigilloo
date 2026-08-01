<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/HelperController.php
//
// The request() helper and the legacy Input facade, both listed as sources in
// docs/06-taint-analysis section "Laravel HTTP". Neither reaches the Request
// object through a parameter, so the receiver check that recognises
// $request->input('x') cannot see either of them.
//
// This is the shape of older Laravel code, which is exactly the code most
// likely to be vulnerable: Input was removed in Laravel 6, so a codebase still
// calling it has gone years without an upgrade.

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;
use Input;

class HelperController
{
    // Positive: the helper called with a key returns that input value, so it is
    // the function form of $request->input('sort').
    public function helper()
    {
        return DB::raw('select * from orders order by ' . request('sort'));
    }

    // Positive: the legacy facade. Resolved through the import above rather than
    // matched on the five letters "Input", so somebody's own Input class does
    // not inherit this.
    public function legacy()
    {
        return DB::raw('select * from orders order by ' . Input::get('sort'));
    }

    // Positive: assigned before use, so the source step lands on the assignment.
    public function assigned()
    {
        $column = request('column');

        return DB::raw("select * from orders order by {$column}");
    }

    // Negative: sanitized after the helper read. Pins that a helper read is an
    // ordinary tainted value rather than a special case that skips the
    // sanitizer table.
    public function escaped()
    {
        return DB::table('orders')->orderByRaw(intval(request('column')));
    }

    // Negative: a function that is not the helper. The name is what identifies
    // this source, so a rule that matched any call with a string argument would
    // fire on most lines in any codebase.
    public function notTheHelper()
    {
        return DB::table('orders')->orderByRaw(config('orders.default_sort'));
    }
}
