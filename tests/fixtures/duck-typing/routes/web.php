<?php
use App\Http\Controllers\DuckController;
use Illuminate\Support\Facades\Route;

Route::get('/duck', [DuckController::class, 'handle']);
