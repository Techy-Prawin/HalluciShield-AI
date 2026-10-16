import httpx
import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent.parent / ".env")

GROQ_API_KEY = os.getenv("LLM_API_KEY", "")
GROQ_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")

# Try different models that might work
models_to_test = [
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "allam-2-7b",
]

headers = {
    "Authorization": f"Bearer {os.getenv('LLM_API_KEY', '')}",
    "Content-Type": "application/json"
}

url = f"{GROQ_BASE_URL.rstrip('/')}/chat/completions"

for model in models_to_test:
    print(f"\n=== Testing model: {model} ===")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You must output only valid JSON. No other text."},
            {"role": "user", "content": 'Output exactly: {"ok":true}'}
        ],
        "stream": False,
        "response_format": {"type": "json_object"},
        "temperature": 0,
        "max_tokens": 32,
    }
    
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = httpx.post(
                f"{GROQ_BASE_URL.rstrip('/')}/chat/completions",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You must output only valid JSON. No other text."},
                        {"role": "user", "content": 'Output exactly: {"ok":true}'}
                    ],
                    "stream": False,
                    "response_format": {"type": "json_object"},
                    "temperature": 0,
                    "max_tokens": 32,
                },
                headers={
                    "Authorization": f"Bearer {os.getenv('LLM_API_KEY', '')}",
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )
            print(f"Model: {model} | Status: {resp.status_code}")
            if resp.status_code == 200:
                print(f"  SUCCESS: {resp.json()}")
                usage = resp.json().get("usage", {})
                print(f"  Usage: {usage}")
            else:
                print(f"  ERROR: {resp.text[:200]}")
    except Exception as e:
        print(f"  Exception: {e}")