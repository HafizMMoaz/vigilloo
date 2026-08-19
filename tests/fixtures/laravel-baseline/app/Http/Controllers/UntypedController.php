<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UntypedController
{
    public function sort($r)
    {
        return DB::table('orders')->orderByRaw($r->sort);
    }
    public function bound($req, $user)
    {
        return DB::table('orders')->orderByRaw($req->sort);
    }
    public function ambiguous($ponytail, $user)
    {
        return DB::table('orders')->orderByRaw($ponytail->sort);
    }
}
