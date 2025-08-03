<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Http;

class ChatTest extends TestCase
{
    use RefreshDatabase;

    protected $user;
    protected $token;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = User::factory()->create();
        $this->token = JWTAuth::fromUser($this->user);
    }

    public function test_authenticated_user_can_send_message()
    {
        Http::fake([
            'chat-service:50051/*' => Http::response(['reply' => 'Hello from bot'], 200),
        ]);

        $response = $this->withHeaders([
            'Authorization' => 'Bearer ' . $this->token,
        ])->postJson('/api/chat', [
            'message' => 'Hello bot',
        ]);

        $response->assertStatus(200)
                 ->assertJson(['reply' => 'Hello from bot']);
    }
}
