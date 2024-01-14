<?php

namespace App\Http\Controllers;

use App\Helpers\Constant;
use App\Models\Otp;
use App\Models\User;
use App\Notifications\SendEmailVerificationNotification;
use App\Notifications\SendResetPasswordNotification;
use Carbon\Carbon;
use Error;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
  // public function __construct()
  // {
  //   $this->middleware('auth:api', ['except' => ['login', 'register', 'refresh', 'logout', 'forgotPassword']]);
  // }

  /**
   * Get a JWT token via given credentials.
   *
   * @param  \Illuminate\Http\Request  $request
   *
   * @return \Illuminate\Http\JsonResponse
   */
  public function login(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|string',
      'password' => 'required|string',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()]);
    }

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
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()]);
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
    $validated = Validator::make($request->all(), [
      'email' => 'required|string|exists:users,email',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {
      $user = User::where('email', $request->email)->first();

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $code = rand(100000, 999999);
      Otp::create([
        "user" => $user->id,
        "otp" => $code,
        "type" => Constant::OTP_RESET_PASSWORD,
        "expires" => Carbon::now()->addMinute(10),
      ]);

      $user->notify(new SendResetPasswordNotification($code));
      return response()->json(["message" => "OTP sent successfully"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function resetPassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'email' => 'required|string|exists:users,email',
      'otp' => 'required|integer',
      'password' => 'required|string|max:25',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {

      $user = User::where('email', $request->email)->first();

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $otp = Otp::where('otp', $request->otp)->where('type', Constant::OTP_RESET_PASSWORD)->where('user', $user->id)->first();

      if (!$otp || $otp->otp != $request->otp) {
        throw new Error("Invalid OTP");
      }

      $isExpired = Carbon::parse($otp->expires)->isPast();
      if ($isExpired) {
        throw new Error("OTP expired");
      }

      // $otp->otp = null;
      // $otp->expires = null;
      // $otp->save();

      $user->password = Hash::make($request->password) ?? Hash::make('password');
      $user->save();

      return response()->json(["message" => "Password reset successfull"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function sendVerificationEmail(Request $request)
  {
    // $validated = Validator::make($request->all(), [
    //   'email' => 'required|string|exists:users,email',
    // ]);

    // if ($validated->fails()) {
    //   return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    // }

    try {
      // $user = User::where('email', $request->email)->first();
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $code = rand(100000, 999999);
      Otp::create([
        "user" => $user->id,
        "otp" => $code,
        "type" => Constant::OTP_VERIFY_EMAIL,
        "expires" => Carbon::now()->addMinute(10),
      ]);

      $user->notify(new SendEmailVerificationNotification($code));
      return response()->json(["message" => "OTP sent successfully"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function verifyEmail(Request $request)
  {
    // $validated = Validator::make($request->all(), [
    //   'email' => 'required|string|exists:users,email',
    //   'otp' => 'required|integer',
    //   'password' => 'required|string|max:25',
    // ]);

    // if ($validated->fails()) {
    //   return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    // }

    try {
      // $user = User::where('email', $request->email)->first();
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $otp = Otp::where('otp', $request->otp)->where('type', Constant::OTP_VERIFY_EMAIL)->where('user', $user->id)->first();

      if (!$otp || $otp->otp != $request->otp) {
        throw new Error("Invalid OTP");
      }

      $isExpired = Carbon::parse($otp->expires)->isPast();
      if ($isExpired) {
        throw new Error("OTP expired");
      }

      // $otp->otp = null;
      // $otp->expires = null;
      // $otp->save();

      $user->email_verified_at = Carbon::now();
      $user->save();

      return response()->json(["message" => "Email verification successfull"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function updatePassword(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'password' => 'required|string|max:25|confirmed',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $user->password = Hash::make($request->password) ?? Hash::make('password');
      $user->save();

      return response()->json(["message" => "Password update successfull"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
  }

  public function update(Request $request)
  {
    $validated = Validator::make($request->all(), [
      'name' => 'required|string|max:255',
      'photo' => 'required|string|max:255',
    ]);

    if ($validated->fails()) {
      return response()->json(['message' => 'Invalid information', 'errors' => $validated->errors()], 422);
    }

    try {
      $user = User::find(Auth::user()->id);

      if (!$user) {
        throw new Error("Invalid user email");
      }

      $user->name = $request->name;
      $user->photo = $request->photo;
      $user->save();

      return response()->json(["message" => "Profile update successfull"]);
    } catch (\Throwable $th) {
      return response()->json(['message' => $th->getMessage()], 403);
    }
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
