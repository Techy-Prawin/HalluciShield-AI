"""
Dependency Analysis Agent API Router.

Provides HTTP endpoint for dependency vulnerability scanning and analysis.
"""

from fastapi import APIRouter, HTTPException, Request, status
from app.agents.dependency_agent import DependencyAnalysisAgent
from app.agents.models import DependencyAnalysisRequest, DependencyAnalysisResponse
from app.security import require_api_key, validate_workspace_path

router = APIRouter(prefix="/api/v1/dependency", tags=["Dependency Analysis Agent"])

agent_instance = DependencyAnalysisAgent()


@router.post("/analyze", response_model=DependencyAnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_dependencies_endpoint(request: DependencyAnalysisRequest, http_request: Request):
    require_api_key(http_request)
    safe_path = validate_workspace_path(request.workspace_path)
    try:
        response = agent_instance.analyze_dependencies(
            repository_id=request.repository_id,
            workspace_path=safe_path,
        )
        return response
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
