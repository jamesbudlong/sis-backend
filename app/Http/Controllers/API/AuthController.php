<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Controllers\API\BaseController as BaseController;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends BaseController
{
    /**
     * Register api
     *
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        $validated = $request->validate([
            'first_name' => 'required',
            'last_name' => 'required',
            'email' => 'required|email',
            'password' => 'required|confirmed',
        ]);

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);

        $user = User::create($input);

        $success['token'] =  $user->createToken('testtoken')->plainTextToken;
        $success['user_id'] = $user->id;
        $success['user_fullname'] =  $user->first_name . ' ' . $user->last_name;

        return $this->sendResponse($success, 'User registered successfully.');
    }

    /**
     * Login api
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            $user = Auth::user();
            $success['token'] =  $user->createToken('testtoken')->plainTextToken;
            $success['user_id'] = $user->id;
            $success['user_fullname'] =  $user->first_name . ' ' . $user->last_name;

            return $this->sendResponse($success, 'User login successfully.');
        }
        else{
            return $this->sendError('Unauthorized.', ['error'=>'Unauthorized']);
        }
    }

    /**
     * Logout api
     *
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
        try{
            auth('sanctum')->user()->currentAccessToken()->delete();
            return $this->sendResponse(null, 'User logged out successfully.');
        }
        catch(Exception $e){
            return $this->sendError('Error.', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Get current user details
     *
     * @return \Illuminate\Http\Response
     */
    public function me(Request $request)
    {
        try{
            $me = $request->user();
            return $this->sendResponse($me, 'User fetched successfully.');
        }
        catch(Exception $e){
            return $this->sendError('Error.', ['error' => $e->getMessage()]);
        }
    }
}
