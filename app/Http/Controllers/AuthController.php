<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        // Validate the incoming request data
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // Find the user by email
         $user = User::where('email', $request->email)->first();

        // Check if the user exists and the password is correct
    if (!$user || !Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.!'],
            ]);
        }

        // Generate a new token for the user
        $token = $user->createToken('my-app-token')->plainTextToken;

        // Return a JSON response with the token
        return response()->json(['token' => $token], 200);
    }




    public function register(Request $request)
    {
        // Validate the incoming request data
        $request->validate([
            'name' => 'required|string|string',
            'email' => 'required|email|string|unique:users',
            'password' => 'required|min:8|string|confirmed',
        ]);

        // Create a new user and hashed the password 
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Generate a new token for the user
        $token = $user->createToken('UserToken')->plainTextToken;

        // Return a json response with the user and token
        return response()->json(['user' => $user, 'token' => $token], 201);
    }

    public function logout(Request $request)
    {
        // Revoke the current access token
        $request->user()->currentAccessToken()->delete();

        // Return a json response indicating successful logout messge
        return response()->json(['message' => 'Logged out successfully'], 200);
    }
}
