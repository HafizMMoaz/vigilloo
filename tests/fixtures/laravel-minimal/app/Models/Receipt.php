<?php
// tests/fixtures/laravel-minimal/app/Models/Receipt.php
//
// Deliberately has no matching ReceiptPolicy: the rule must still fire, and
// say that no policy is defined rather than that one exists and is ignored.

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Receipt extends Model
{
    protected $fillable = ['note'];
}
