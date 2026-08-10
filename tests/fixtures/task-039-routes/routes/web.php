<?php
use App\Http\Controllers\AdminController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\PostController;
use App\Http\Controllers\ItemController;
use Illuminate\Support\Facades\Route;

Route::get('/home', 'HomeController@index')->name('home');

Route::prefix('admin')->middleware(['auth', 'verified'])->name('admin.')->group(function () {
    Route::get('/dashboard', [AdminController::class, 'index'])->name('dashboard');
    
    Route::group(['prefix' => 'users', 'middleware' => 'can:manage-users', 'as' => 'users.'], function () {
        Route::post('/create', [UserController::class, 'create'])->name('create');
        Route::get('/{user}', [UserController::class, 'show'])->middleware('throttle:60,1')->name('show');
    });
});

Route::middleware(['api'])->group(function () {
    Route::resource('posts', PostController::class);
    Route::apiResource('items', ItemController::class);
});
