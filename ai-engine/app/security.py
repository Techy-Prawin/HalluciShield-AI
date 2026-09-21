"""
Centralized Security Utilities for HalluciShield AI Engine.

Provides:
- Path traversal prevention (C-2)
- SSRF protection (H-1)
- LLM prompt sanitization (H-2/H-3)
- API key authentication (H-4/H-6)
- Rate limiting (H-7)
- Security headers (L-1)
- Upload validation (H-5)
"""

import ipaddress
import logging
import os
import re
import secrets
import socket
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 120
MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".toml", ".yaml", ".yml", ".json",
    ".xml", ".txt", ".md", ".cfg", ".ini", ".lock",
}

# When set (docker-compose mounts the shared named volume at /workspace on the
# AI engine too), analysis is restricted to the shared workspace root so the
# engine can never read arbitrary host paths the backend did not stage.
WORKSPACE_ROOT_ENV = "HALLUCISHIELD_WORKSPACE_ROOT"


def _configured_workspace_root() -> Optional[str]:
    raw = os.environ.get(WORKSPACE_ROOT_ENV, "")
    raw = raw.strip()
    return str(Path(raw).resolve()) if raw else None

BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(previous|all|above)\s+instructions",
    r"(?i)you\s+are\s+now\s+",
    r"(?i)new\s+instructions?\s*:",
    r"(?i)disregard\s+",
    r"(?i)override\s+",
    r"(?i)jailbreak",
    r"(?i)DAN\s+mode",
    r"(?i)act\s+as\s+if",
    r"(?i)pretend\s+you\s+are",
]


def validate_workspace_path(workspace_path: str, allowed_base: Optional[str] = None) -> str:
    if not workspace_path or not workspace_path.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="workspace_path is required")
    resolved = Path(workspace_path).resolve()
    raw_parts = Path(workspace_path).parts
    if ".." in raw_parts:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path traversal detected in workspace_path")
    if allowed_base is None:
        allowed_base = _configured_workspace_root()
    if allowed_base:
        allowed = Path(allowed_base).resolve()
        try:
            resolved.relative_to(allowed)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Path outside allowed workspace root")
    return str(resolved)


def validate_url_safe(url: str) -> bool:
    if not url:
        return True
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL format")
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"URL scheme '{parsed.scheme}' not allowed")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL must have a hostname")
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
        for _, _, _, _, sockaddr in resolved_ips:
            ip = ipaddress.ip_address(sockaddr[0])
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"URL resolves to internal network: {hostname}")
    except HTTPException:
        raise
    except socket.gaierror:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Could not resolve hostname: {hostname}")
    except Exception as e:
        logger.warning(f"[Security] URL validation error: {e}")
    return True


def sanitize_for_llm_prompt(text: str, max_length: int = 50000) -> str:
    if not text:
        return ""
    sanitized = text[:max_length]
    sanitized = re.sub(r"<\|[^|]*\|>", "[REDACTED]", sanitized)
    sanitized = re.sub(r"```\s*(system|assistant|user)", "``` [redacted]", sanitized)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, sanitized):
            logger.warning(f"[Security] Prompt injection pattern detected in input")
            sanitized = f"[SUSPICIOUS INPUT DETECTED]\n{sanitized}\n[/SUSPICIOUS INPUT]"
            break
    return sanitized


def validate_file_upload(filename: str, content_length: int) -> None:
    if content_length > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"File too large. Max: {MAX_UPLOAD_SIZE_BYTES // (1024*1024)}MB")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"File extension '{ext}' not allowed")


def get_client_id(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = RATE_LIMIT_MAX_REQUESTS, window_seconds: int = RATE_LIMIT_WINDOW_SECONDS):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_id = get_client_id(request)
        now = time.time()
        cutoff = now - self.window_seconds
        self._requests[client_id] = [t for t in self._requests[client_id] if t > cutoff]
        if len(self._requests[client_id]) >= self.max_requests:
            return Response(content='{"detail":"Rate limit exceeded"}', status_code=429, media_type="application/json")
        self._requests[client_id].append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


def require_api_key(request: Request) -> None:
    api_key = os.environ.get("HALLUCISHIELD_API_KEY", "")
    if not api_key:
        return
    provided = request.headers.get(API_KEY_HEADER, "")
    if not provided or not secrets.compare_digest(provided, api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
