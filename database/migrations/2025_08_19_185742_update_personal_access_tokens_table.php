<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            // Supprimer l'ancienne colonne
            $table->dropColumn('tokenable_id');

            // Ajouter la nouvelle colonne en UUID
            $table->uuid('tokenable_id')->after('tokenable_type');
        });
    }
    public function down(): void
    {
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            $table->dropColumn('tokenable_id');
            $table->unsignedBigInteger('tokenable_id')->after('tokenable_type');
        });
    }
};
