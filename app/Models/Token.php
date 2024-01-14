<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Token extends Model
{
  /**
   * The attributes that are mass assignable.
   *
   * @var array
   */
  protected $fillable = [
    'user',
    'token',
    'type',
    'expires',
  ];

  /**
   * The attributes that should be cast.
   *
   * @var array<string, string>
   */
  protected $casts = [
    // 'expires' => 'datetime',
  ];

  /**
   * Get the phone associated with the user.
   */
  // public function user(): HasOne
  // {
  //   return $this->hasMany(User::class);
  // }
}
