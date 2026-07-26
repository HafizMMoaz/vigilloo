<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/InvoiceController.php
//
// One action per row of the missing-authorization table. Every action is
// deliberately free of request data and of Eloquent writes, so nothing here
// can produce a taint finding and confuse the counts.

namespace App\Http\Controllers;

use App\Http\Requests\CheckedInvoiceRequest;
use App\Http\Requests\StubInvoiceRequest;
use App\Models\Invoice;
use App\Models\Receipt;
use App\Support\Token;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class InvoiceController extends Controller
{
    // Authenticated, model-bound, nothing authorizes it, and InvoicePolicy
    // exists. The finding this slice is for.
    public function show(Invoice $invoice)
    {
        return $invoice;
    }

    // Same, but no ReceiptPolicy exists anywhere.
    public function showReceipt(Receipt $receipt)
    {
        return $receipt;
    }

    public function guarded(Invoice $invoice)
    {
        $this->authorize('view', $invoice);

        return $invoice;
    }

    public function viaMiddleware(Invoice $invoice)
    {
        return $invoice;
    }

    public function viaGate(Invoice $invoice)
    {
        if (Gate::denies('view', $invoice)) {
            abort(403);
        }

        return $invoice;
    }

    public function viaCan(Request $request, Invoice $invoice)
    {
        if ($request->user()->cannot('view', $invoice)) {
            abort(403);
        }

        return $invoice;
    }

    // Validation is not authorization: authorize() returning a bare true is
    // the make:request stub, and must not clear the rule.
    public function viaStubRequest(StubInvoiceRequest $request, Invoice $invoice)
    {
        return $invoice;
    }

    public function viaRealRequest(CheckedInvoiceRequest $request, Invoice $invoice)
    {
        return $invoice;
    }

    public function publicShow(Invoice $invoice)
    {
        return $invoice;
    }

    public function inGroup(Invoice $invoice)
    {
        return $invoice;
    }

    public function unreadable(Invoice $invoice)
    {
        return $invoice;
    }

    public function nonModel(Token $token)
    {
        return $token;
    }
}
