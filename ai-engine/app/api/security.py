"""
Security Analysis Agent API Router.

Provides HTTP endpoint for security vulnerability scanning using Semgrep.
"""

from fastapi import APIRouter, HTTPException, Request, status
from app.agents.security_agent import SecurityAnalysisAgent
from app.agents.models import SecurityAnalysisRequest, SecurityAnalysisResponse
from app.security import require_api_key, validate_workspace_path

router = APIRouter(prefix="/api/v1/security", tags=["Security Analysis Agent"])

agent_instance = SecurityAnalysisAgent()


@router.post("/scan", response_model=SecurityAnalysisResponse, status_code=status.HTTP_200_OK)
async def scan_security_endpoint(request: SecurityAnalysisRequest, http_request: Request):
    """
    Scan source code repository for security vulnerabilities using Semgrep.

    Detects:
    - SQL Injection (CWE-89)
    - Cross-Site Scripting (CWE-79)
    - Hardcoded Secrets (CWE-798)
    - Command Injection (CWE-78)
    - Path Traversal (CWE-22)
    - Insecure JWT Usage (CWE-347)

    Returns structured JSON findings with normalized severity and CWE mapping.
    """
    require_api_key(http_request)
    # --- SECURITY (CRIT-3): validate workspace_path before file-walking ---
    try:
        safe_path = validate_workspace_path(request.workspace_path)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    # --- End security check ---

    try:
        response = agent_instance.analyze_security(
            repository_id=request.repository_id,
            workspace_path=safe_path,
            scan_rules=request.scan_rules,
        )
        return response
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security analysis failed. See server logs for details.",
        )
