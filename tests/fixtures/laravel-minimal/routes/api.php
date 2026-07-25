<?php
// tests/fixtures/laravel-minimal/routes/api.php

use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;

Route::post('/orders/search', [OrderController::class, 'search']);
Route::get('/orders/recent', [OrderController::class, 'recent']);
Route::get('/orders/display', [OrderController::class, 'display']);
