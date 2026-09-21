"""
System-wide Health & Connectivity Test Suite for HalluciShield AI
Verifies that all baseline services (Backend, AI Engine) respond with HTTP 200 OK.
"""

import httpx
import pytest

BACKEND_HEALTH_URL = "http://localhost:4000/api/v1/health"
AI_ENGINE_HEALTH_URL = "http://localhost:8000/api/v1/health"

@pytest.mark.asyncio
async def test_backend_health_connectivity():
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(BACKEND_HEALTH_URL)
            assert response.status_code == 200
            data = response.json()
            assert data["service"] == "hallucishield-backend"
            assert data["status"] == "ok"
        except httpx.ConnectError:
            pytest.skip("Backend service is not currently running locally on port 4000.")

@pytest.mark.asyncio
async def test_ai_engine_health_connectivity():
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(AI_ENGINE_HEALTH_URL)
            assert response.status_code == 200
            data = response.json()
            assert data["service"] == "hallucishield-ai-engine"
            assert data["status"] == "ok"
        except httpx.ConnectError:
            pytest.skip("AI Engine service is not currently running locally on port 8000.")
