<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class DuckController {
    public function handle(Request $request, $duck) {
        $id = $request->input('id');
        $duck->quack($id);
    }
}

class FastDuck {
    public function quack($id) {
        DB::select("SELECT * FROM ducks WHERE id = " . $id);
    }
}

class SlowDuck {
    public function quack($id) {
        DB::select("SELECT * FROM ducks WHERE id = " . $id);
    }
}
