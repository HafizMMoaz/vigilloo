<?php
namespace App\Http\Controllers;
class TestController {
    public function upload(Request $request) {
        $name = $request->file('avatar')->getClientOriginalName();
        $request->file('avatar')->storeAs('avatars', $name);
        
        dd($name);
        dump($name);
        ray($name);
        var_dump($name);
        
        $user->password = md5($request->password);
        $user->password = sha1($request->password);
        $checksum = md5($file); // should NOT fire
        
        $token = rand();
        $salt = mt_rand();
        $user->password_reset_token = rand();
        $age = rand(); // should NOT fire
        
        $arr = [
            'password' => md5('secret'),
            'reset_token' => mt_rand(),
            'age' => rand(), // should NOT fire
        ];
    }
}
