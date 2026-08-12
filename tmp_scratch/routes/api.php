<?php
use App\Http\Controllers\ThingController;
use Illuminate\Support\Facades\Route;
Route::post('/things', [ThingController::class, 'act']);
