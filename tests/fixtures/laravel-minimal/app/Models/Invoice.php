<?php
// tests/fixtures/laravel-minimal/app/Models/Invoice.php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Invoice extends Model
{
    protected $fillable = ['note'];
}
