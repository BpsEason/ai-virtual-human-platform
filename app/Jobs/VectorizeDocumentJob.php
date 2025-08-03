<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Http;

class VectorizeDocumentJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $documentId;
    protected $chunk;

    public function __construct($documentId, $chunk)
    {
        $this->documentId = $documentId;
        $this->chunk = $chunk;
    }

    public function handle()
    {
        $response = Http::post('http://vectorization-service:8000/vectorize', [
            'document_id' => $this->documentId,
            'content' => $this->chunk,
        ]);

        if ($response->failed()) {
            throw new \Exception("向量化服務失敗: " . $response->body());
        }
    }
}
