<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/ReceiptController.php
//
// authorizeResource() in the constructor authorizes every action at once, so
// no action of this controller may be reported.

namespace App\Http\Controllers;

use App\Models\Receipt;

class ReceiptController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Receipt::class, 'receipt');
    }

    public function show(Receipt $receipt)
    {
        return $receipt;
    }
}
