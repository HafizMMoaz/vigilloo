<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/SlugController.php
//
// Route parameters injected into the action signature. docs/06-taint-analysis:
// "Route parameters injected into controller signatures are sources:
// public function show(Request $r, string $slug) - $slug is attacker-controlled."
//
// Laravel binds a URI segment to an action parameter *by name*, so the whole
// rule turns on matching {slug} in the URI to $slug in the signature. The
// negatives below are what keep that from becoming "every string parameter is
// tainted", which would fire on half the methods in a real application.

namespace App\Http\Controllers;

use App\Models\Invoice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SlugController
{
    // Positive: {slug} is bound to $slug, read straight into the sink argument.
    // The Request parameter beside it is deliberate - it is the exact signature
    // the spec gives, and the walk has to see past it to the second parameter.
    public function show(Request $request, string $slug)
    {
        return DB::table('pages')->orderByRaw($slug);
    }

    // Positive: assigned before use, so the source step lands on the assignment
    // rather than on the sink argument. Same source, different place in the walk.
    public function ordered(string $column)
    {
        $order = $column;

        return DB::raw("select * from pages order by {$order}");
    }

    // Negative: model-bound. The URI segment names a record, and what is missing
    // here is authorization, not escaping - that is laravel.missing-authorization,
    // a different rule with different advice. Tainting it would report an
    // injection on an Eloquent object that cannot reach a string sink.
    public function bound(Invoice $invoice)
    {
        return DB::table('pages')->orderByRaw($invoice->column);
    }

    // Negative: PHP coerces an int-typed parameter before the body runs, so a
    // string payload never arrives. This is the same reasoning the walk already
    // applies to an (int) cast, and it has to agree with it.
    public function paged(int $page)
    {
        return DB::raw("select * from pages limit {$page}");
    }

    // Negative: not a URI parameter at all. The route below declares no {filter},
    // so Laravel never binds this argument from the URL. Matching on the type
    // alone rather than on the name would fire here.
    public function filtered(string $filter = 'name')
    {
        return DB::table('pages')->orderByRaw($filter);
    }
}
