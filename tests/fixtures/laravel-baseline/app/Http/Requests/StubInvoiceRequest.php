<?php
// tests/fixtures/laravel-minimal/app/Http/Requests/StubInvoiceRequest.php
//
// What `php artisan make:request` generates once someone flips the false to
// true to make validation work. It authorizes nothing.

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class StubInvoiceRequest extends FormRequest
{
    public function authorize()
    {
        return true;
    }

    public function rules()
    {
        return ['note' => 'string'];
    }
}
