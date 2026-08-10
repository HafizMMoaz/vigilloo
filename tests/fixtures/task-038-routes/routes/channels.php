<?php
use Illuminate\Support\Facades\Route;
Route::get('/channels', [App\Http\Controllers\ChannelController::class, 'index']);
