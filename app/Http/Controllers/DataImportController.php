<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Jobs\ProcessDocumentImport;
use App\Models\KnowledgeBase;
use Illuminate\Support\Facades\Auth;

class DataImportController extends Controller
{
    public function import(Request $request)
    {
        $validated = $request->validate([
            'document_name' => 'required|string',
            'content' => 'required|string',
        ]);

        $document = KnowledgeBase::create([
            'document_name' => $validated['document_name'],
            'content' => $validated['content'],
            'metadata' => [
                'user_id' => Auth::id(),
                'imported_at' => now(),
            ],
        ]);

        ProcessDocumentImport::dispatch($document);

        return response()->json(['message' => '文件已排入佇列進行處理'], 202);
    }
}
