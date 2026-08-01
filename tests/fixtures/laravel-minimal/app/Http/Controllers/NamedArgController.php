<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/NamedArgController.php
//
// Named arguments, listed in docs/03-parser section "PHP features that must be
// handled correctly". They break argument-precise sinks in a way that is easy
// to miss: the sink table says "argument 0 of whereRaw is the SQL", and with
// `whereRaw(bindings: [], sql: $tainted)` the tainted value sits at position 1
// while position 0 holds an empty array.
//
// Position stops meaning anything once a name is written, so the walk has to
// read the name. Getting this wrong is silent in both directions - a miss on
// the reordered form, and a false positive if the safe binding argument were
// ever mistaken for the query.

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class NamedArgController
{
    // Positive: named, and written in the declared order. The value is still in
    // position 0, so this fires with or without name resolution - it is the
    // control for the reordered case below.
    public function ordered(Request $request)
    {
        return DB::table('orders')->whereRaw(sql: $request->input('filter'));
    }

    // Positive: named and REORDERED. This is the case that was silently missed:
    // argument 0 is the empty bindings array, and the injectable SQL is at 1.
    public function reordered(Request $request)
    {
        return DB::table('orders')->whereRaw(
            bindings: [],
            sql: $request->input('filter')
        );
    }

    // Negative: the safe form written with names. The query is a constant and
    // the request data is a binding, which is the whole point of bindings. A
    // name-aware rule must not start reporting the parameterised form.
    public function bound(Request $request)
    {
        return DB::table('orders')->whereRaw(
            sql: 'status = ?',
            bindings: [$request->input('status')]
        );
    }

    // Negative: reordered AND safe. Reading names correctly has to hold when the
    // reordering works in the tool's favour too, or the fix trades one silent
    // miss for one noisy false positive.
    public function boundReordered(Request $request)
    {
        return DB::table('orders')->whereRaw(
            bindings: [$request->input('status')],
            sql: 'status = ?'
        );
    }
}
