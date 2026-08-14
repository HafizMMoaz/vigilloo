<?php
namespace App\Http\Controllers;
use Illuminate\Support\Facades\DB;

class DuckClass {
    public function dynamicCall($x) {
        DB::statement($x);
    }
}
