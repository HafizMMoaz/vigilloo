<?php
use App\Http\Controllers\FooController;
Route::post('/test', [FooController::class, 'act']);
