from fastapi import APIRouter, HTTPException, Request, status
from app.agents.hallucination_agent import HallucinationDetectionAgent
from app.agents.models import DetectionRequest, DetectionResponse
from app.security import require_api_key, validate_workspace_path

router = APIRouter(prefix="/api/v1/hallucination", tags=["Hallucination Detection Agent"])

agent_instance = HallucinationDetectionAgent()


@router.post("/detect", response_model=DetectionResponse, status_code=status.HTTP_200_OK)
async def detect_hallucinations_endpoint(request: DetectionRequest, http_request: Request):
    require_api_key(http_request)
    safe_path = validate_workspace_path(request.workspace_path)
    try:
        response = agent_instance.detect_hallucinations(
            repository_id=request.repository_id,
            workspace_path=safe_path,
        )
        return response
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
