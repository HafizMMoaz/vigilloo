<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/OrderController.php

namespace App\Http\Controllers;

use App\Repositories\OrderRepository;
use Illuminate\Http\Request;

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
}
