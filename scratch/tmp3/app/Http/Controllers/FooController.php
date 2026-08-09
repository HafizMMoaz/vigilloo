<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\UnknownFacade;
class FooController
{
    public function act(Request $request)
    {
        UnknownFacade::doSomething($request->input('x'));
    }
}
