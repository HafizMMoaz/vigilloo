<?php
use Illuminate\Support\Facades\Route;
Route::get('/console', [App\Http\Controllers\ConsoleController::class, 'index']);
