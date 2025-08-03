<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use App\Models\ChatSession;
use Illuminate\Support\Facades\Log;

class ChatController extends Controller
{
    public function sendMessage(Request $request)
    {
        $validated = $request->validate([
            'message' => 'required|string',
        ]);

        try {
            // 呼叫 gRPC 對話微服務
            // 這裡需要 gRPC PHP 擴展和客戶端
            // 暫時用 HTTP 模擬
            $response = Http::post('http://chat-service:50051/chat/SendMessage', [
                'message' => $validated['message'],
            ]);

            if ($response->failed()) {
                Log::error('Chat service failed', ['response' => $response->body()]);
                return response()->json(['error' => 'Chat service failed'], 500);
            }
            
            $reply = $response->json()['reply'];

            // 儲存聊天會話
            ChatSession::create([
                'user_id' => auth()->id(),
                'user_message' => $validated['message'],
                'bot_reply' => $reply,
            ]);

            return response()->json(['reply' => $reply]);
        } catch (\Exception $e) {
            Log::error('Chat controller exception', ['exception' => $e->getMessage()]);
            return response()->json(['error' => 'Internal Server Error'], 500);
        }
    }
}
