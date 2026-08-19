<?php
// tests/fixtures/laravel-minimal/app/Policies/InvoicePolicy.php

namespace App\Policies;

use App\Models\Invoice;

class InvoicePolicy
{
    public function view($user, Invoice $invoice)
    {
        return $user->id === $invoice->user_id;
    }

    public function delete($user, Invoice $invoice)
    {
        return $user->id === $invoice->user_id;
    }
}
