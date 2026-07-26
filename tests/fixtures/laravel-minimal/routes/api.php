<?php
// tests/fixtures/laravel-minimal/routes/api.php

use App\Http\Controllers\OrderController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

Route::post('/orders/search', [OrderController::class, 'search']);
Route::get('/orders/recent', [OrderController::class, 'recent']);
Route::get('/orders/display', [OrderController::class, 'display']);

Route::post('/users', [UserController::class, 'store']);
Route::post('/posts', [UserController::class, 'storePost']);
Route::post('/profiles', [UserController::class, 'storeProfile']);
Route::post('/users/narrowed', [UserController::class, 'storeNarrowed']);
Route::post('/users/validated', [UserController::class, 'storeValidated']);
Route::post('/users/lookup', [UserController::class, 'lookup']);
Route::post('/posts/force', [UserController::class, 'forcePost']);
Route::put('/users/{user}', [UserController::class, 'bound']);
Route::put('/posts/{post}', [UserController::class, 'boundGuarded']);
