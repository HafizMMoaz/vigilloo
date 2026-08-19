<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/MagicController.php
//
// Magic property access on the Request, which docs/06-taint-analysis calls
// "commonly missed". Laravel's Request implements __get(), so $request->sort
// returns the same attacker-supplied value as $request->input('sort') and
// carries exactly the same danger. The walk recognised only the method form
// before TASK-027, so this shape was a silent false negative.
//
// The negative below is the case that decides whether the rule is usable: the
// receiver, not the syntax, is what makes a property fetch a source.

namespace App\Http\Controllers;

use App\Support\Token;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class MagicController
{
    // Positive: read straight into the sink argument, with nothing stored in a
    // variable first. The source step has to come from the sink argument here.
    public function sort(Request $request)
    {
        return DB::table('orders')->orderByRaw($request->sort);
    }

    // Positive: assigned first, so the source step is emitted by the assignment.
    // Same read, different place in the walk, and both have to work.
    public function search(Request $request)
    {
        $column = $request->column;

        return DB::raw("select * from orders order by {$column}");
    }

    // Negative: an ordinary object that happens to have a property. Nothing
    // about `->value` is dangerous; it is dangerous because the receiver is a
    // Request. A rule keyed on the syntax alone would report every property
    // read in the codebase, which is how a tool gets switched off.
    public function fromToken(Token $token)
    {
        return DB::table('orders')->orderByRaw($token->value);
    }

    // Negative: sanitized after the magic read. Pins that a magic property is
    // an ordinary tainted value and not a special case that bypasses the
    // sanitizer table.
    public function escaped(Request $request)
    {
        return DB::table('orders')->orderByRaw(intval($request->column));
    }
}
