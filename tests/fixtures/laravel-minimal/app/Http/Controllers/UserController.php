<?php
// tests/fixtures/laravel-minimal/app/Http/Controllers/UserController.php

namespace App\Http\Controllers;

use App\Models\Post;
use App\Models\Profile;
use App\Models\User;
use Illuminate\Http\Request;

class UserController
{
    public function store(Request $request)
    {
        return User::create($request->all());
    }

    public function storePost(Request $request)
    {
        return Post::create($request->all());
    }

    public function storeProfile(Request $request)
    {
        return Profile::create($request->all());
    }

    public function storeNarrowed(Request $request)
    {
        return User::create($request->only(['name', 'email']));
    }

    public function storeValidated(Request $request)
    {
        return User::create($request->validated());
    }

    public function lookup(Request $request)
    {
        return User::updateOrCreate($request->all(), ['status' => 'active']);
    }

    public function forcePost(Request $request)
    {
        $post = Post::find($request->input('id'));

        return $post->forceFill($request->all());
    }

    public function bound(Request $request, User $user)
    {
        return $user->update($request->all());
    }

    public function boundGuarded(Request $request, Post $post)
    {
        return $post->update($request->all());
    }
}
