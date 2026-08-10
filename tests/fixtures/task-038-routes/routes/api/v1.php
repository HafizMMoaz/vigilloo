<?php
use Illuminate\Support\Facades\Route;
Route::get('/v1/users', [App\Http\Controllers\UserController::class, 'index']);
