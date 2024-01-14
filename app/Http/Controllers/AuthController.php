<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Notifications\SendResetPasswordNotification;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
  public function __construct()
  {
    $this->middleware('auth:api', ['except' => ['login', 'register', 'refresh', 'logout']]);
  }

  /**
   * Get a JWT token via given credentials.
   *
   * @param  \Illuminate\Http\Request  $request
   *
   * @return \Illuminate\Http\JsonResponse
   */
  public function login(Request $request)
  {
    $this->validate($request, [
      'email' => 'required|string',
      'password' => 'required|string',
    ]);

    $credentials = $request->only(['email', 'password']);

    if (!$token = Auth::attempt($credentials)) {
      return response()->json(['message' => 'Invalid credentials'], 401);
    }

    return $this->respondWithToken($token);
  }

  public function register(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'name' => 'required|string|max:255',
      'email' => 'required|string|max:255|unique:users,email',
      'password' => 'required|string|max:25',
    ]);

    if ($validated->fails()) {
      return response()->json(['status' => 'error', 'errors' => $validated->errors()]);
    }

    $body = [
      "name" => $request->name,
      "email" => $request->email,
      "password" => Hash::make($request->password) ?? Hash::make('password'),
    ];

    $user = User::create($body);

    $user->assignRole('user');

    return $this->login($request);
  }

  /**
   * Get the authenticated User
   *
   * @return \Illuminate\Http\JsonResponse
   */
  public function profile()
  {
    return response()->json(auth()->user());
  }

  /**
   * Log the user out (Invalidate the token).
   *
   * @return \Illuminate\Http\JsonResponse
   */
  public function logout()
  {
    auth()->logout();

    return response()->json(['message' => 'Successfully logged out']);
  }

  /**
   * Refresh a token.
   *
   * @return \Illuminate\Http\JsonResponse
   */
  public function refreshTokens()
  {
    return $this->respondWithToken(Auth::refresh());
  }

  public function forgotPassword(Request $request)
  {
    try {
      //code...
      $user = User::find(Auth::user()->id);
      $user->notify(new SendResetPasswordNotification(123456));
      return response()->json(["message" => "OTP sent successfully"]);
    } catch (\Throwable $th) {
      //throw $th;
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function resetPassword(Request $request)
  {
    // $user = Auth::user();
    // Auth::user()->notify(new SendResetPasswordNotification(123456));
    return response()->json(["message" => "OTP sent successfully"]);
  }

  public function sendVerificationEmail(Request $request)
  {
    return response()->json(["message" => "OTP sent successfully"]);
  }

  public function verifyEmail(Request $request)
  {
    return response()->json(["message" => "OTP sent successfully"]);
  }

  public function updatePassword(Request $request)
  {
    return response()->json(["message" => "OTP sent successfully"]);
  }

  public function update(Request $request)
  {
    return response()->json(["message" => "OTP sent successfully"]);
  }

  /**
   * Get the token array structure.
   *
   * @param string $token
   *
   * @return \Illuminate\Http\JsonResponse
   */
  protected function respondWithToken($token)
  {
    // return response()->json([
    //   'access_token' => $token,
    //   'token_type' => 'bearer',
    //   'expires_in' => Auth::factory()->getTTL() * 60
    // ]);
    $user = Auth::user();

    return response()->json([
      'user' => $user,
      'tokens' => [
        'access' => [
          'token' => $token,
          'expires' => Auth::factory()->getTTL() * 60,
        ],
        'refresh' => [
          'token' => JWTAuth::fromUser($user),
          'expires' => config('jwt.refresh_ttl') * 60,
        ],
      ],
    ]);
  }
}
