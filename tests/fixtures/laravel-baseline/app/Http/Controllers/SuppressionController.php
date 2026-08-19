<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SuppressionController extends Controller
{
    public function validSuppression(Request $request)
    {
        // vigilloo-ignore laravel.raw-query -- validated locally
        DB::raw($request->input('q'));
    }

    public function bareSuppression(Request $request)
    {
        // vigilloo-ignore laravel.raw-query
        DB::raw($request->input('q'));
    }

    public function wrongRuleSuppression(Request $request)
    {
        // vigilloo-ignore laravel.mass-assignment -- actually raw query
        DB::raw($request->input('q'));
    }

    // vigilloo-ignore laravel.missing-authorization -- intentional public route
    public function structuralSuppression(\App\Models\User $user)
    {
        return response()->json(['status' => 'ok', 'user' => $user->id]);
    }
}
