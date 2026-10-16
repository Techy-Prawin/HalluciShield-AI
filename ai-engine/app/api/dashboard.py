"""
Dashboard API Router.

Serves the Risk Assessment Dashboard, Patch Recommendation Dashboard,
Explainable Recommendation Dashboard, and Patch Approval Dashboard HTML pages.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
import os
from app.security import require_api_key

router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(require_api_key)],
)

_static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")


@router.get("/risk", response_class=HTMLResponse)
async def get_risk_dashboard():
    """
    Serve the Risk Assessment Dashboard.
    
    Provides visualizations for:
    - Overall risk score with gauge
    - Category risk breakdowns (hallucination, security, dependency)
    - Findings by severity chart
    - Top issues for each category
    - Actionable recommendations
    """
    dashboard_path = os.path.join(_static_dir, "dashboard.html")
    
    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    return HTMLResponse(content=content)


@router.get("/recommendation", response_class=HTMLResponse)
async def get_recommendation_dashboard():
    """
    Serve the Patch Recommendation Dashboard.
    
    Provides visualizations for:
    - Ranked patch table with confidence scores
    - Safety threshold status
    - Top patch recommendation with reasoning
    - Evidence breakdown for each candidate
    """
    dashboard_path = os.path.join(_static_dir, "recommendation.html")
    
    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    return HTMLResponse(content=content)


@router.get("/explanation", response_class=HTMLResponse)
async def get_explanation_dashboard():
    """
    Serve the Explainable Recommendation Dashboard.

    Provides visualizations for:
    - Why This Patch checklist
    - Confidence score with feature contribution breakdown
    - Validation evidence from stored results
    - Before/after security findings comparison
    """
    dashboard_path = os.path.join(_static_dir, "explanation.html")

    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()

    return HTMLResponse(content=content)


@router.get("/approval", response_class=HTMLResponse)
async def get_approval_dashboard():
    """
    Serve the Patch Approval Dashboard.

    Provides:
    - Review original vs patched code with diff
    - Vulnerability details
    - Validation results and confidence score
    - Accept/Reject buttons with mandatory developer ID
    - Approval history
    """
    dashboard_path = os.path.join(_static_dir, "approval.html")

    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()

    return HTMLResponse(content=content)


@router.get("/monitoring", response_class=HTMLResponse)
async def get_monitoring_dashboard():
    """
    Serve the Runtime Security Monitoring Dashboard.

    Provides:
    - Event counts and severity breakdown
    - Security alerts with risk scores
    - Event processing pipeline visualization
    - Top anomaly endpoints
    - Simulate events for testing
    """
    dashboard_path = os.path.join(_static_dir, "monitoring.html")

    with open(dashboard_path, "r", encoding="utf-8") as f:
        content = f.read()

    return HTMLResponse(content=content)
