<?php

namespace App\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use App\Models\KnowledgeBase;
use App\Jobs\VectorizeDocumentJob;

class ProcessDocumentImport implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    protected $document;

    public function __construct(KnowledgeBase $document)
    {
        $this->document = $document;
    }

    public function handle()
    {
        // 處理文件，切塊，然後分派給向量化任務
        // 實際邏輯需在此實現
        $chunks = $this->splitDocumentIntoChunks($this->document->content);

        foreach ($chunks as $chunk) {
            VectorizeDocumentJob::dispatch($this->document->id, $chunk);
        }
    }

    protected function splitDocumentIntoChunks($content)
    {
        // 簡單的分塊邏輯，實際應使用更精細的技術
        return explode('.', $content);
    }
}
