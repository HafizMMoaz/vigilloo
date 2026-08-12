<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
class ThingController
{
    public function act(Request $request)
    {
        return view('show', ['x' => $request->input('x')]);
    }
}
