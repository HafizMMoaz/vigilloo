<?php
use Illuminate\Support\Facades\Route;
Route::post('/custom/action', [App\Http\Controllers\CustomController::class, 'action']);
