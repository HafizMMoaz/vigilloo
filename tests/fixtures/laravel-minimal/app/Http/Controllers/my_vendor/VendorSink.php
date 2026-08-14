<?php
namespace App\Http\Controllers\my_vendor;
use Illuminate\Support\Facades\DB;

class VendorSink {
    public function doSink($x) {
        DB::statement($x);
    }
}
