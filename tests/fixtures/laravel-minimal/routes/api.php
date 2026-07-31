<?php
// tests/fixtures/laravel-minimal/routes/api.php

use App\Http\Controllers\InvoiceController;
use App\Http\Controllers\LegacyController;
use App\Http\Controllers\OrderController;
use App\Http\Controllers\ReceiptController;
use App\Http\Controllers\ReportController;
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

// Missing-authorization cases. Everything below is model-bound; what differs
// is what guards it.
Route::get('/invoices/{invoice}', [InvoiceController::class, 'show'])->middleware('auth');
Route::get('/receipts/{receipt}', [InvoiceController::class, 'showReceipt'])->middleware('auth');
Route::get('/invoices/{invoice}/guarded', [InvoiceController::class, 'guarded'])
    ->middleware('auth');
Route::get('/invoices/{invoice}/mw', [InvoiceController::class, 'viaMiddleware'])
    ->middleware(['auth', 'can:view,invoice']);
Route::get('/invoices/{invoice}/gate', [InvoiceController::class, 'viaGate'])
    ->middleware('auth:sanctum');
Route::get('/invoices/{invoice}/can', [InvoiceController::class, 'viaCan'])->middleware('auth');
Route::get('/invoices/{invoice}/stub', [InvoiceController::class, 'viaStubRequest'])
    ->middleware('auth');
Route::get('/invoices/{invoice}/checked', [InvoiceController::class, 'viaRealRequest'])
    ->middleware('auth');
Route::get('/invoices/{invoice}/public', [InvoiceController::class, 'publicShow']);
Route::get('/tokens/{token}', [InvoiceController::class, 'nonModel'])->middleware('auth');
Route::get('/receipts/{receipt}/resource', [ReceiptController::class, 'show'])
    ->middleware('auth');

$extra = 'can:view,invoice';
Route::get('/invoices/{invoice}/unreadable', [InvoiceController::class, 'unreadable'])
    ->middleware('auth')
    ->middleware($extra);

Route::middleware(['auth'])->group(function () {
    Route::get('/invoices/{invoice}/grouped', [InvoiceController::class, 'inGroup']);
});

// The DB facade, reached through a repository. Three sinks and two negatives.
Route::get('/reports/status', [ReportController::class, 'byStatus']);
Route::get('/reports/totals', [ReportController::class, 'totals']);
Route::post('/reports/purge', [ReportController::class, 'purge']);
Route::get('/reports/bound', [ReportController::class, 'bound']);
Route::get('/reports/columns', [ReportController::class, 'columns']);

// PHP superglobals, read directly rather than through the Request object. The
// route is what makes them reachable: a sink no entry point reaches is not a
// finding here, by design.
Route::get('/legacy/search', [LegacyController::class, 'search']);
Route::get('/legacy/host', [LegacyController::class, 'host']);
Route::get('/legacy/root', [LegacyController::class, 'documentRoot']);
Route::get('/legacy/local', [LegacyController::class, 'localArray']);
