<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        # Get the response, validate and store into fields...
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'
        ]);

        # Create user
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        # Create token 
        $token = $user->createToken('myapptoken')->plainTextToken;

        # Response - successful
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request)
    {
        # Get the response, validate and store into fields...
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string'
        ]);

        # Check email
        $user = User::where('email', $fields['email'])->first();

        # Check password
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                    'message' => 'Bad credentials'
                ], 401);
        }
        
        # Create token 
        $token = $user->createToken('myapptoken')->plainTextToken;

        # Response - successful
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    # Logout and destroy token
    public function logout(Request $request)
     {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Logged out'
        ];
    }
}
