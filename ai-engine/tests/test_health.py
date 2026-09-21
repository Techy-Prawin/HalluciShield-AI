from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "HalluciShield AI Engine"
    assert data["status"] == "active"

def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "hallucishield-ai-engine"
    assert data["status"] == "ok"
    assert "llm_config" in data
    assert data["llm_config"]["provider"] == "openai_compatible"
    assert data["llm_config"]["api_key_configured"] is not None
