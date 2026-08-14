<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php

namespace App\Http\Controllers;

use App\Repositories\OrderRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class OrderController
{
    public function __construct(private OrderRepository $orders)
    {
    }

    public function search(Request $request)
    {
        $sort = $request->input('sort');

        return $this->orders->search($sort);
    }

    public function recent(Request $request)
    {
        return $this->orders->recent();
    }

    public function display(Request $request)
    {
        $sort = $request->input('sort');

        return view('orders.show', compact('sort'));
    }

    public function dynamic(Request $request, $duck)
    {
        $duck->dynamicCall($request->input('dynamic_input'));
    }

    public function weak(Request $request)
    {
        $safe = strip_tags($request->input('weak_input'));
        DB::statement($safe);
    }

    public function vendorTest(Request $request)
    {
        $v = new my_vendor\VendorSink();
        $v->doSink($request->input('vendor_input'));
    }
}
