<?php

namespace Database\Seeders;

use App\Models\User;
use Carbon\Carbon;
use Illuminate\Database\Seeder;

class UsersTableSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Add 3 users to the database
        for ($index = 1; $index <= 3; $index++) {
            User::create([
                'username' => "user$index",
                'email' => "user$index@gmail.com",
                'password' => bcrypt('Aa123456'),
                'email_verified_at' => Carbon::now(), // Preenche com a data e hora atual
                'active' => true
            ]);
        }
    }
}
