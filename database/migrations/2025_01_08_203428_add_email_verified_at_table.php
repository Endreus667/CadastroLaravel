<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
{
    Schema::table('users', function (Blueprint $table) {
        // Verificar se a coluna não existe antes de adicioná-la
        if (!Schema::hasColumn('users', 'email_verified_at')) {
            $table->dateTime('email_verified_at')->nullable()->default(null);
        }
    });
}
    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('email_verified_at');
        });
    }
};
