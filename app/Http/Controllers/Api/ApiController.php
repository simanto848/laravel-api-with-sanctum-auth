<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class ApiController extends Controller
{
    // Register API
    public function register(Request $request){
        $data = $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|confirmed|min:8',
        ]);

        User::create($data);

        return response()->json([
            'status' => true,
            'message' => 'User registered successfully',
        ]);
    }

    // Login API
    public function login(Request $request){
        $data = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // User check by email
        $user = User::where('email', $data['email'])->first();

        if(!empty($user)) {
            if(Hash::check($data['password'], $user->password)){
                $token = $user->createToken('auth_token')->plainTextToken;

                return response()->json([
                    'status' => true,
                    'message' => 'User logged in successfully',
                    'token' => $token,
                ]);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid credentials',
                ]);
            }
        } else {
            return response()->json([
                'status' => false,
                'message' => 'User not found',
            ]);
        }
    }

    // Profile API
    public function profile(){
        $userData = auth()->user();
        return response()->json([
            'status' => true,
            'message' => 'User profile data',
            'data' => $userData,
            'id' => auth()->user()->id
        ]);
    }

    // Logout API
    public function logout(){
        auth()->user()->tokens()->delete();
        return response()->json([
            'status' => true,
            'message' => 'User logged out successfully',
        ]);
    }
}
