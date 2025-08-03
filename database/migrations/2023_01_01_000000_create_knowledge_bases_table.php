<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('knowledge_bases', function (Blueprint $table) {
            $table->id();
            $table->string('document_name');
            $table->longText('content');
            $table->json('metadata')->nullable();
            $table->timestamps();
        });
        // 假設分區邏輯
        // DB::statement("ALTER TABLE knowledge_bases PARTITION BY KEY (id) PARTITIONS 4;");
    }

    public function down(): void
    {
        Schema::dropIfExists('knowledge_bases');
    }
};
