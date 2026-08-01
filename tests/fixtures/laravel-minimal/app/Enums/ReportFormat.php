<?php
// tests/fixtures/laravel-minimal/app/Enums/ReportFormat.php
//
// A backed enum whose methods hold the sinks, listed in docs/03-parser section
// "PHP features that must be handled correctly".
//
// The sinks are deliberately inside the enum rather than in the controller. A
// finding whose sink sits in the *caller* proves nothing about enums: the walk
// unions taint over a call's children, so tainted data passed to any unresolved
// callee stays tainted in the result and the caller-side sink fires whether or
// not the callee was ever found. Only a sink in here requires the enum to have
// been extracted, resolved and walked into.
//
// Enums arrived in PHP 8.1 and are now the idiomatic way to model a fixed set of
// values, so an enum that owns the query for each of its cases is ordinary code.

namespace App\Enums;

use Illuminate\Support\Facades\DB;

enum ReportFormat: string
{
    case Csv = 'csv';
    case Json = 'json';

    // Positive: the sink is here, so this finding exists only if the enum was
    // extracted, the static call resolved to it, and the walk entered the body.
    public static function purge(string $table): void
    {
        DB::unprepared("truncate table {$table}");
    }

    // Negative: parameterised, in an enum body. The walk now goes in here, so the
    // ordinary rules have to apply once it does - argument precision included.
    // Without this, "the walk can see enums" would be free to mean "anything
    // reached through an enum is a finding".
    public static function forStatus(string $status): array
    {
        return DB::select('select * from reports where status = ?', [$status]);
    }
}
