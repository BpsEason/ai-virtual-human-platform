from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_vectorize_endpoint():
    response = client.post("/vectorize", json={"document_id": 1, "content": "Test document"})
    assert response.status_code == 200
    assert response.json()["message"] == "已成功上傳至 Pinecone"
