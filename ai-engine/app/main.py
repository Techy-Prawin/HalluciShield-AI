from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.security import RateLimitMiddleware, SecurityHeadersMiddleware
from app.api.health import router as health_router
from app.api.analyzer import router as analyzer_router
from app.api.hallucination import router as hallucination_router
from app.api.security import router as security_router
from app.api.dependency import router as dependency_router
from app.api.risk import router as risk_router
from app.api.dashboard import router as dashboard_router
from app.api.patches import router as patches_router
from app.api.recommendation import router as recommendation_router
from app.api.patch_approval import router as patch_approval_router
from app.api.monitoring import router as monitoring_router
from app.api.learning import router as learning_router
from app.api.experiments import router as experiments_router
from app.api.analytics import router as analytics_router

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Adaptive Multi-Agent Confidence Framework AI Service"
)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in (settings.cors_origins or "http://localhost:3000").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(health_router)
app.include_router(analyzer_router)
app.include_router(hallucination_router)
app.include_router(security_router)
app.include_router(dependency_router)
app.include_router(risk_router)
app.include_router(dashboard_router)
app.include_router(patches_router)
app.include_router(recommendation_router)
app.include_router(patch_approval_router)
app.include_router(monitoring_router)
app.include_router(learning_router)
app.include_router(experiments_router)
app.include_router(analytics_router)

@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": settings.version,
        "status": "active",
        "docs": "/docs",
        "healthCheck": "/api/v1/health",
        "analyzeEndpoint": "/api/v1/analyzer/analyze",
        "detectEndpoint": "/api/v1/hallucination/detect",
        "securityScanEndpoint": "/api/v1/security/scan",
        "dependencyAnalysisEndpoint": "/api/v1/dependency/analyze",
        "riskAssessmentEndpoint": "/api/v1/risk/repositories/{id}/risk",
        "dashboardEndpoint": "/api/v1/dashboard/risk",
        "patchGenerationEndpoint": "/api/v1/vulnerabilities/{id}/generate-patches",
        "patchValidationEndpoint": "/api/v1/vulnerabilities/{id}/validate-patch",
        "validateCandidatesEndpoint": "/api/v1/vulnerabilities/{id}/validate-candidates",
        "rankPatchesEndpoint": "/api/v1/vulnerabilities/{id}/rank-patches",
        "recommendationEndpoint": "/api/v1/vulnerabilities/{id}/recommendation",
        "explanationEndpoint": "/api/v1/vulnerabilities/{id}/patches/{patch_id}/explanation",
        "patchReviewEndpoint": "/api/v1/vulnerabilities/{id}/patches/{patch_id}/review",
        "patchApprovalEndpoint": "/api/v1/vulnerabilities/{id}/patches/{patch_id}/approve",
        "patchRejectionEndpoint": "/api/v1/vulnerabilities/{id}/patches/{patch_id}/reject",
        "approvalStatusEndpoint": "/api/v1/vulnerabilities/{id}/patches/{patch_id}/approval-status",
        "approvalsHistoryEndpoint": "/api/v1/vulnerabilities/{id}/approvals",
        "approvalDashboard": "/api/v1/dashboard/approval",
        "recommendationDashboard": "/api/v1/dashboard/recommendation",
        "explanationDashboard": "/api/v1/dashboard/explanation",
        "monitoringDashboard": "/api/v1/dashboard/monitoring",
        "monitoringEventsEndpoint": "/api/v1/monitoring/events",
        "monitoringAlertsEndpoint": "/api/v1/monitoring/alerts",
        "monitoringSimulateEndpoint": "/api/v1/monitoring/simulate",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)
