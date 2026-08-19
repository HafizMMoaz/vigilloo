<?php
// tests/fixtures/laravel-minimal/routes/api.php

use App\Http\Controllers\InvoiceController;
use App\Http\Controllers\EnumController;
use App\Http\Controllers\HelperController;
use App\Http\Controllers\LegacyController;
use App\Http\Controllers\MagicController;
use App\Http\Controllers\NamedArgController;
use App\Http\Controllers\NullsafeController;
use App\Http\Controllers\OrderController;
use App\Http\Controllers\ReceiptController;
use App\Http\Controllers\ReportController;
use App\Http\Controllers\SlugController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\BranchController; use Illuminate\Support\Facades\Route;

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

// Magic property access on the Request. $request->sort is __get() and returns
// the same value $request->input('sort') would, so the two forms are one
// finding twice over - and only one of them was visible before TASK-027.
Route::get('/magic/sort', [MagicController::class, 'sort']);
Route::get('/magic/search', [MagicController::class, 'search']);
Route::get('/magic/token/{token}', [MagicController::class, 'fromToken']);
Route::get('/magic/escaped', [MagicController::class, 'escaped']);

// Route parameters injected into the action signature (TASK-028). Laravel binds
// a URI segment to an action parameter by name, so {slug} arrives as $slug and
// is as attacker-controlled as $request->input('slug') is.
Route::get('/pages/{slug}', [SlugController::class, 'show']);
Route::get('/pages/{column}/ordered', [SlugController::class, 'ordered']);
Route::get('/pages/{invoice}/bound', [SlugController::class, 'bound']);
Route::get('/pages/{page}/paged', [SlugController::class, 'paged']);
// No {filter} segment, so nothing binds $filter - the negative that stops the
// rule from tainting every string parameter it sees.
Route::get('/pages/filtered', [SlugController::class, 'filtered']);

// The request() helper and the legacy Input facade (TASK-029). Neither reaches
// the Request through a parameter, so the receiver check that sees
// $request->input('x') cannot see either of them.
Route::get('/helper/sort', [HelperController::class, 'helper']);
Route::get('/helper/legacy', [HelperController::class, 'legacy']);
Route::get('/helper/assigned', [HelperController::class, 'assigned']);
Route::get('/helper/escaped', [HelperController::class, 'escaped']);
Route::get('/helper/config', [HelperController::class, 'notTheHelper']);

// The nullsafe operator (TASK-030). `$request?->input('x')` reads what
// `$request->input('x')` reads - tree-sitter just spells it as a different node
// type, so a walk keyed on the arrow form is blind to it.
Route::get('/nullsafe/sort', [NullsafeController::class, 'sort']);
Route::get('/nullsafe/magic', [NullsafeController::class, 'magic']);
Route::get('/nullsafe/assigned', [NullsafeController::class, 'assigned']);
Route::get('/nullsafe/ordinary/{invoice}', [NullsafeController::class, 'ordinary']);
Route::get('/nullsafe/escaped', [NullsafeController::class, 'escaped']);

// Named arguments (TASK-030). `whereRaw(bindings: [], sql: $x)` puts the
// injectable SQL at position 1, so an index-only sink reads the empty bindings
// array and loses the finding - and reads the binding on the safe mirror image.
Route::get('/named/ordered', [NamedArgController::class, 'ordered']);
Route::get('/named/reordered', [NamedArgController::class, 'reordered']);
Route::get('/named/bound', [NamedArgController::class, 'bound']);
Route::get('/named/bound-reordered', [NamedArgController::class, 'boundReordered']);

// Enum methods (TASK-030). An enum is an ordinary call target - its methods have
// bodies and parameters - but enum declarations were not extracted at all, so a
// call into one resolved to nothing and the walk stopped without counting it.
Route::post('/enum/purge', [EnumController::class, 'purge']);
Route::get('/enum/status', [EnumController::class, 'status']);
Route::get('/branch', [BranchController::class, 'branchSanitized']);
Route::get('/branch/safe', [BranchController::class, 'fullySanitized']);



$dynamic_route = '/orders/dyn';
Route::get($dynamic_route, [App\Http\Controllers\OrderController::class, 'dynamic']);
Route::get('/orders/test/weak', [App\Http\Controllers\OrderController::class, 'weak']);
Route::get('/orders/test/vendor', [App\Http\Controllers\OrderController::class, 'vendorTest']);
Route::post('/login', [App\Http\Controllers\UserController::class, 'login']);

Route::get('/unsubscribe', [App\Http\Controllers\UserController::class, 'unsubscribe']);
Route::get('/confirm', [App\Http\Controllers\UserController::class, 'confirm'])->middleware('signed');
Route::get('/approve', [App\Http\Controllers\UserController::class, 'approve'])->middleware('auth');

// Unauthenticated route cases (TASK-071)
Route::post('/unauth/update', [App\Http\Controllers\UserController::class, 'updateProfile']); // positive
Route::middleware(['auth'])->group(function () {
    Route::post('/unauth/grouped-update', [App\Http\Controllers\UserController::class, 'updateProfile']); // negative
});
Route::get('/unauth/read', [App\Http\Controllers\UserController::class, 'readProfile']); // negative (GET)
Route::post('/unauth/signed', [App\Http\Controllers\UserController::class, 'signedUpdate'])->middleware('signed'); // negative (signed)
