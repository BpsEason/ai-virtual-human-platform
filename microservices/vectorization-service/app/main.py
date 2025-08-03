from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer

# 初始化 FastAPI
app = FastAPI()

# 初始化 Pinecone
pinecone = Pinecone(api_key=os.environ.get('PINECONE_API_KEY'), environment=os.environ.get('PINECONE_ENVIRONMENT'))
index = pinecone.Index('my-index')

# 初始化 SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')

class Document(BaseModel):
    document_id: int
    content: str

@app.post("/vectorize")
async def vectorize_document(doc: Document):
    try:
        vector = model.encode(doc.content).tolist()
        index.upsert(vectors=[
            {'id': str(doc.document_id), 'values': vector, 'metadata': {'content': doc.content}}
        ])
        return {"message": "已成功上傳至 Pinecone"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
