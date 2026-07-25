<?php
// tests/fixtures/laravel-minimal/app/Repositories/OrderRepository.php

namespace App\Repositories;

use Illuminate\Support\Facades\DB;

class OrderRepository
{
    public function search(string $sort)
    {
        return DB::table('orders')->orderByRaw("created_at {$sort}")->get();
    }

    public function recent()
    {
        return DB::table('orders')->orderBy('created_at', 'desc')->limit(10)->get();
    }
}
