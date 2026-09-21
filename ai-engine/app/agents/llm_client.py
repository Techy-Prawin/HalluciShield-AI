import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def chat_json(
    prompt: str,
    timeout: float = 30.0,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
) -> str:
    """
    Send a chat completion request to the configured OpenAI-compatible provider
    (LLM_BASE_URL) and return the raw text reply.

    Returns an empty string on any failure so callers can fall back to
    deterministic logic.
    """
    messages = [{"role": "user", "content": prompt}]
    try:
        headers = {}
        if settings.llm_api_key:
            headers["Authorization"] = f"Bearer {settings.llm_api_key}"
        url = f"{settings.llm_base_url.rstrip('/')}/chat/completions"
        payload: dict = {
            "model": settings.default_llm_model,
            "messages": messages,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return content if isinstance(content, str) else ""
            logger.debug(f"[LLMClient] HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        logger.debug(f"[LLMClient] LLM query failed: {e}")
    return ""