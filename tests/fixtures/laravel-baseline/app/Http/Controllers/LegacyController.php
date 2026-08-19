<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/LegacyController.php
//
// PHP superglobals, which the walk could not see at all before TASK-026. This is
// the shape of older Laravel code, which is exactly the code most likely to be
// vulnerable: it reaches past the Request object and reads the array directly.
//
// $_SERVER is the case that decides whether the rule is usable. It is half
// attacker-controlled and half server configuration, so a table keyed on the
// variable alone either misses the header or fabricates a finding on a
// filesystem path the attacker never touched.

namespace App\Http\Controllers;

use Illuminate\Support\Facades\DB;

class LegacyController
{
    // Positive: every key of $_GET is attacker-controlled, so the key is not
    // inspected at all.
    public function search()
    {
        return DB::raw('select * from orders order by ' . $_GET['sort']);
    }

    // Positive: assigned before use, so the source step is emitted by the
    // assignment rather than by the sink argument.
    public function host()
    {
        $host = $_SERVER['HTTP_HOST'];

        return DB::raw("select * from sites where host = '{$host}'");
    }

    // Negative: DOCUMENT_ROOT is server configuration. docs/06-taint-analysis
    // names it as the $_SERVER key that is not attacker-controlled, and it is
    // read here through the same superglobal that fires two methods above.
    public function documentRoot()
    {
        return DB::raw("select * from files where root = '{$_SERVER['DOCUMENT_ROOT']}'");
    }

    // Negative: an ordinary local array subscript. The walk now has a rule for
    // reading an array by key, and it must not follow that rule into every
    // array a developer ever wrote.
    public function localArray()
    {
        $config = ['sort' => 'created_at'];

        return DB::raw('select * from orders order by ' . $config['sort']);
    }
}
