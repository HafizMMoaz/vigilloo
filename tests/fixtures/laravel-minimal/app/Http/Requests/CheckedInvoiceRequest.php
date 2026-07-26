<?php
// tests/fixtures/laravel-minimal/app/Http/Requests/CheckedInvoiceRequest.php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class CheckedInvoiceRequest extends FormRequest
{
    public function authorize()
    {
        return $this->user()->id === $this->route('invoice')->user_id;
    }

    public function rules()
    {
        return ['note' => 'string'];
    }
}
