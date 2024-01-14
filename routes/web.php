<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->get('/', function () use ($router) {
    return $router->app->version();
});


$router->group(['prefix' => 'v1'], function () use ($router) {
  $router->group(['prefix' => 'auth'], function () use ($router) {
    $router->post('/register', 'AuthController@register');
    $router->post('/login', 'AuthController@login');

    $router->post('/forgot-password', 'AuthController@forgotPassword');
    $router->post('/reset-password', 'AuthController@resetPassword');
  });

  $router->group(['prefix' => 'auth', 'middleware' => 'auth'], function () use ($router) {
    $router->get('/profile', 'AuthController@profile');
    $router->post('/logout', 'AuthController@logout');
    $router->post('/refresh-tokens', 'AuthController@refreshTokens');
    $router->post('/send-verification-email', 'AuthController@sendVerificationEmail');
    $router->post('/verify-email', 'AuthController@verifyEmail');
    // $router->post('/send-otp', 'AuthController@send-otp');
    // $router->post('/verify-otp', 'AuthController@verify-otp');
    $router->put('/update-password', 'AuthController@updatePassword');
    $router->put('/update', 'AuthController@update');
    // $router->post('/update-photo', 'AuthController@update-photo');
  });

  $router->group(['middleware' => 'auth'], function () use ($router) {

    $router->group(['middleware' => ['role:admin|moderator']], function () {
      //
    });
  });
});


// php -S localhost:8000 -t ./public
