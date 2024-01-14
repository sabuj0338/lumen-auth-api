<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;

class UsersTableSeeder extends Seeder
{
  /**
   * Run the database seeds.
   */
  public function run(): void
  {

    Role::create(['name' => 'super-admin']);
    Role::create(['name' => 'admin']);
    Role::create(['name' => 'moderator']);
    Role::create(['name' => 'user']);

    User::create([
      'name' => 'Sabuj Islam',
      'email' => 'sabuj0338@gmail.com',
      'password' => Hash::make('password')
    ]);
  }
}
