<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/BranchController.php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class BranchController extends Controller
{
    public function branchSanitized(Request $request)
    {
        $order = $request->input('order');
        if ($request->has('safe')) {
            $order = intval($order);
        }
        
        DB::table('users')->orderByRaw($order)->get();
    }

    public function fullySanitized(Request $request)
    {
        $order = $request->input('order');
        if ($request->has('safe')) {
            $order = intval($order);
        } else {
            $order = (int) $order;
        }
        
        DB::table('users')->orderByRaw($order)->get();
    }
}
