"""
Risk Assessment Engine API Router.

Provides HTTP endpoint for comprehensive repository risk assessment
combining hallucination, security, and dependency analysis findings.
"""

import time
from fastapi import APIRouter, HTTPException, Request, status
from app.agents.risk_engine import RiskEngine
from app.agents.hallucination_agent import HallucinationDetectionAgent
from app.agents.security_agent import SecurityAnalysisAgent
from app.agents.dependency_agent import DependencyAnalysisAgent
from app.agents.models import (
    RiskAssessmentRequest,
    RiskAssessmentResponse,
    RiskAssessment,
)
from app.security import require_api_key, validate_workspace_path

router = APIRouter(prefix="/api/v1/risk", tags=["Risk Assessment Engine"])

risk_engine = RiskEngine()
hallucination_agent = HallucinationDetectionAgent()
security_agent = SecurityAnalysisAgent()
dependency_agent = DependencyAnalysisAgent()


@router.get(
    "/repositories/{repository_id}/risk",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
)
async def get_repository_risk(
    repository_id: str,
    workspace_path: str = ".",
    http_request: Request = None,
):
    require_api_key(http_request)
    safe_path = validate_workspace_path(workspace_path)
    start_time = time.time()
    try:
        hallucination_response = hallucination_agent.detect_hallucinations(
            repository_id=repository_id, workspace_path=safe_path)
        security_response = security_agent.analyze_security(
            repository_id=repository_id, workspace_path=safe_path)
        dependency_response = dependency_agent.analyze_dependencies(
            repository_id=repository_id, workspace_path=safe_path)
        assessment = risk_engine.assess_risk(
            repository_id=repository_id,
            hallucination_response=hallucination_response,
            security_response=security_response,
            dependency_response=dependency_response)
        duration_ms = int((time.time() - start_time) * 1000)
        assessment.analysis_duration_ms = duration_ms
        return RiskAssessmentResponse(
            repository_id=repository_id,
            risk_assessment=assessment,
            analysis_duration_ms=duration_ms)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")


@router.post(
    "/assess",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
)
async def assess_risk_endpoint(request: RiskAssessmentRequest, http_request: Request):
    require_api_key(http_request)
    safe_path = validate_workspace_path(request.workspace_path)
    start_time = time.time()
    try:
        hallucination_response = hallucination_agent.detect_hallucinations(
            repository_id=request.repository_id, workspace_path=safe_path)
        security_response = security_agent.analyze_security(
            repository_id=request.repository_id, workspace_path=safe_path)
        dependency_response = dependency_agent.analyze_dependencies(
            repository_id=request.repository_id, workspace_path=safe_path)
        assessment = risk_engine.assess_risk(
            repository_id=request.repository_id,
            hallucination_response=hallucination_response,
            security_response=security_response,
            dependency_response=dependency_response)
        duration_ms = int((time.time() - start_time) * 1000)
        assessment.analysis_duration_ms = duration_ms
        return RiskAssessmentResponse(
            repository_id=request.repository_id,
            risk_assessment=assessment,
            analysis_duration_ms=duration_ms)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error")
