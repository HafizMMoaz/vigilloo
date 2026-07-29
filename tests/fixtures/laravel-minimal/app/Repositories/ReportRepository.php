<?php
// tests/fixtures/laravel-minimal/app/Repositories/ReportRepository.php
//
// The DB facade, which is the form the taint walk could not see until static
// calls landed. Every method here is a case the sink table has to tell apart.

namespace App\Repositories;

use Illuminate\Support\Facades\DB;

class ReportRepository
{
    // Positive: the query itself is built from user data.
    public function byStatus(string $status)
    {
        return DB::select("select * from orders where status = '{$status}'");
    }

    // Positive: raw() is the canonical Laravel SQL injection. Returned rather
    // than passed straight into ->addSelect(...), deliberately. Both forms are
    // reported identically, but the nested one also hands a tainted value to a
    // builder method whose receiver the walk cannot resolve, so it records a
    // lost trail beside a finding that already captured the same data. That is
    // the ponytail at the "$this->prop" check in taint.py, not this rule's
    // business, and putting it in the fixture would bake it into the
    // no-lost-trails assertion as though it were expected.
    public function totalExpression(string $column)
    {
        return DB::raw("sum({$column}) as total");
    }

    // Positive: statement() and unprepared() run whatever they are handed.
    public function purge(string $table)
    {
        DB::unprepared("truncate table {$table}");
    }

    // Negative: parameterised. The query is a constant and the user data is a
    // binding, which is the whole distinction the rule has to make. Flagging
    // this is what teaches developers to stop reading the report.
    public function bound(string $status)
    {
        return DB::select('select * from orders where status = ?', [$status]);
    }

    // Negative: the builder's select() is a column list, not a query. Same
    // method name as the sink above and a completely different meaning, which
    // is why the sink table is keyed on the receiver and not on the name.
    public function columns()
    {
        return DB::table('orders')->select(['id', 'status'])->get();
    }
}
