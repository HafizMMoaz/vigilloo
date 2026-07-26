<?php
// tests/fixtures/laravel-minimal/app/Models/Profile.php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Profile extends Model
{
    protected $fillable = ['name', 'is_admin'];
}
