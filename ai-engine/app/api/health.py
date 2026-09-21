from fastapi import APIRouter
from datetime import datetime, timezone
import httpx
from app.config import settings

router = APIRouter(prefix="/api/v1", tags=["Health"])

@router.get("/health")
async def health_check():
    # Check the configured LLM provider connectivity
    llm_healthy = False
    try:
        headers = {}
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.llm_base_url.rstrip('/')}/models", headers=headers)
            if resp.status_code == 200:
                llm_healthy = True
    except Exception:
        llm_healthy = False

    return {
        "service": "hallucishield-ai-engine",
        "status": "ok",
        "version": settings.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "llm_config": {
            "provider": "openai_compatible",
            "provider_name": "groq",
            "model": settings.default_llm_model,
            "provider_base_url": settings.llm_base_url,
            "api_key_configured": bool(settings.llm_api_key),
            "llm_reachable": llm_healthy
        }
    }
