from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel
from app.analyzer.engine import RepositoryAnalyzer
from app.analyzer.models import AnalysisResult
from app.security import require_api_key, validate_workspace_path

router = APIRouter(prefix="/api/v1/analyzer", tags=["Static Analyzer"])

analyzer_instance = RepositoryAnalyzer()


class AnalyzeRequest(BaseModel):
    repository_id: str
    workspace_path: str


@router.post("/analyze", response_model=AnalysisResult, status_code=status.HTTP_200_OK)
async def analyze_repository_endpoint(request: AnalyzeRequest, http_request: Request):
    """
    Statically analyze source code in workspace_path WITHOUT EXECUTING IT.
    Extracts programming languages, symbols, dependencies, and security-relevant constructs.
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
        result = analyzer_instance.analyze_repository(
            repository_id=request.repository_id,
            workspace_path=safe_path,
        )
        return result
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Repository analysis failed. See server logs for details.",
        )
