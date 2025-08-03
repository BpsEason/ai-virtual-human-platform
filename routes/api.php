<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DataImportController;
use App\Http\Controllers\ChatController;

Route::post('auth/register', [AuthController::class, 'register']);
Route::post('auth/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('data/import', [DataImportController::class, 'import']);
    Route::post('chat', [ChatController::class, 'sendMessage']);
});

Route::get('/health', function () {
    return response()->json(['status' => 'ok']);
});
