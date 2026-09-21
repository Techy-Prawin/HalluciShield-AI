from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    SUSPICIOUS = "SUSPICIOUS"
    NOT_VERIFIED = "NOT_VERIFIED"


class FindingType(str, Enum):
    HALLUCINATED_PACKAGE = "HALLUCINATED_PACKAGE"
    PHANTOM_METHOD = "PHANTOM_METHOD"
    UNKNOWN_API = "UNKNOWN_API"
    SUSPICIOUS_IMPORT = "SUSPICIOUS_IMPORT"
    SIGNATURE_MISMATCH = "SIGNATURE_MISMATCH"
    UNSUPPORTED_SECURITY_ASSUMPTION = "UNSUPPORTED_SECURITY_ASSUMPTION"
    SUSPICIOUS_DEPENDENCY = "SUSPICIOUS_DEPENDENCY"


class VerificationEvidence(BaseModel):
    symbol_name: str
    check_type: str  # REGISTRY_VERIFICATION, AST_SYMBOL_VERIFICATION, SIGNATURE_CHECK
    registry: Optional[str] = None  # npm, PyPI, Maven, Standard Library
    registry_status: Optional[str] = None  # 200_OK, 404_NOT_FOUND, SYMBOL_NOT_FOUND
    facts: List[str] = Field(default_factory=list)
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class HallucinationFinding(BaseModel):
    finding_id: str
    type: FindingType
    file: str
    line: int
    evidence: VerificationEvidence
    explanation: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float  # 0.0 to 1.0 explainable score
    verification_status: VerificationStatus
    verification_method: str  # DETERMINISTIC_REGISTRY_CHECK, AST_SYMBOL_VERIFICATION, LLM_HYBRID_REASONING


class DetectionRequest(BaseModel):
    repository_id: str
    workspace_path: str


class DetectionResponse(BaseModel):
    repository_id: str
    total_findings: int
    confirmed_findings_count: int
    likely_findings_count: int
    suspicious_findings_count: int
    findings: List[HallucinationFinding] = Field(default_factory=list)
    analysis_duration_ms: int


# ============================================================
# Security Analysis Agent Models
# ============================================================

class VulnerabilitySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING = "CROSS_SITE_SCRIPTING"
    HARDCODED_SECRET = "HARDCODED_SECRET"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    INSECURE_JWT = "INSECURE_JWT"
    INSECURE_DEPENDENCY = "INSECURE_DEPENDENCY"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    BROKEN_AUTHENTICATION = "BROKEN_AUTHENTICATION"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    UNKNOWN = "UNKNOWN"


class SecurityFinding(BaseModel):
    finding_id: str
    type: VulnerabilityType
    severity: VulnerabilitySeverity
    cwe: Optional[str] = None
    file: str
    line: int
    end_line: Optional[int] = None
    evidence: str
    description: str
    scanner: str = "semgrep"
    rule_id: Optional[str] = None
    confidence: float = 0.95
    fix_recommendation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SemgrepScanResult(BaseModel):
    rule_id: str
    message: str
    severity: str
    file: str
    line: int
    end_line: Optional[int] = None
    line_range: Optional[List[int]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    extra: Dict[str, Any] = Field(default_factory=dict)


class SecurityAnalysisRequest(BaseModel):
    repository_id: str
    workspace_path: str
    scan_rules: Optional[List[str]] = None


class SecurityAnalysisResponse(BaseModel):
    repository_id: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[SecurityFinding] = Field(default_factory=list)
    scan_duration_ms: int
    scanner: str = "semgrep"


# ============================================================
# Dependency Analysis Agent Models
# ============================================================

class DependencyType(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    GRADLE = "gradle"
    UNKNOWN = "unknown"


class DependencyFindingType(str, Enum):
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    SUSPICIOUS_DEPENDENCY = "SUSPICIOUS_DEPENDENCY"
    VERSION_INCONSISTENCY = "VERSION_INCONSISTENCY"
    UNUSED_DEPENDENCY = "UNUSED_DEPENDENCY"
    HALLUCINATED_PACKAGE = "HALLUCINATED_PACKAGE"
    SECURITY_RISK = "SECURITY_RISK"
    DEPRECATED_PACKAGE = "DEPRECATED_PACKAGE"
    OUTDATED_PACKAGE = "OUTDATED_PACKAGE"
    DUPLICATE_DEPENDENCY = "DUPLICATE_DEPENDENCY"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"


class DependencySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DependencyInfo(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: DependencyType
    file_path: str
    line_number: Optional[int] = None
    is_dev_dependency: bool = False
    is_optional: bool = False
    source_section: Optional[str] = None  # dependencies, devDependencies, etc.


class DependencyFinding(BaseModel):
    finding_id: str
    type: DependencyFindingType
    severity: DependencySeverity
    package_name: str
    ecosystem: DependencyType
    file: str
    line: Optional[int] = None
    evidence: str
    description: str
    cwe: Optional[str] = None
    confidence: float = 0.9
    fix_recommendation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DependencyAnalysisRequest(BaseModel):
    repository_id: str
    workspace_path: str


class DependencyAnalysisResponse(BaseModel):
    repository_id: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[DependencyFinding] = Field(default_factory=list)
    dependencies_scanned: int = 0
    analysis_duration_ms: int


# ============================================================
# Risk Assessment Engine Models
# ============================================================

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CategoryRisk(BaseModel):
    category: str  # hallucination, security, dependency
    risk_score: float  # 0.0 to 100.0
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    top_issues: List[Dict[str, Any]] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    repository_id: str
    timestamp: str
    overall_risk_score: float  # 0.0 to 100.0
    overall_risk_level: RiskLevel
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    hallucination_risk: CategoryRisk
    security_risk: CategoryRisk
    dependency_risk: CategoryRisk
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    analysis_duration_ms: int = 0


class RiskAssessmentRequest(BaseModel):
    repository_id: str
    workspace_path: str


class RiskAssessmentResponse(BaseModel):
    repository_id: str
    risk_assessment: RiskAssessment
    analysis_duration_ms: int


# ============================================================
# Multi-Candidate Patch Generation Models
# ============================================================

class PatchCandidate(BaseModel):
    patch_id: str
    modified_code: str
    explanation: str
    security_strategy: str
    assumptions: List[str] = Field(default_factory=list)
    expected_effect: str
    potential_side_effects: List[str] = Field(default_factory=list)
    is_not_applicable: bool = False


class PatchGenerationRequest(BaseModel):
    vulnerability_id: str
    vulnerability_type: str
    severity: str
    file: str
    line: int
    vulnerable_code: str
    surrounding_code: str = ""
    description: str = ""
    cwe: Optional[str] = None


class PatchGenerationResponse(BaseModel):
    vulnerability_id: str
    candidates: List[PatchCandidate] = Field(default_factory=list)
    generation_duration_ms: int
    model_used: str
    retry_count: int = 0


# ============================================================
# Secure Patch Validation Sandbox Models
# ============================================================

class SandboxConfig(BaseModel):
    cpu_limit: float = Field(default=1.0, description="CPU cores limit for container")
    memory_limit: str = Field(default="512m", description="Memory limit (e.g. 512m, 1g)")
    execution_timeout: int = Field(default=30, description="Max execution time in seconds")
    max_processes: int = Field(default=64, description="Max number of processes in container")
    tmpfs_size: str = Field(default="256m", description="Size of tmpfs mount")


class CompilationResult(BaseModel):
    success: bool
    language: str = ""
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None


class TestResult(BaseModel):
    success: bool
    framework: str = ""
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    output: str = ""
    duration_ms: int = 0
    failures: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None


class SecurityScanResult(BaseModel):
    success: bool
    scanner: str = ""
    vulnerabilities_found: int = 0
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None


class PerformanceResult(BaseModel):
    execution_time_ms: int = 0
    memory_peak_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    io_read_bytes: int = 0
    io_write_bytes: int = 0
    details: Dict[str, Any] = Field(default_factory=dict)


class SandboxValidationRequest(BaseModel):
    patch: PatchCandidate
    repository_id: str = ""
    workspace_path: str = ""
    file_path: str
    original_code: str
    language: str = "python"
    test_command: Optional[str] = None
    compile_command: Optional[str] = None
    scan_command: Optional[str] = None
    sandbox_config: Optional[SandboxConfig] = None


class SandboxStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class SandboxValidationResponse(BaseModel):
    patch_id: str
    compilation: CompilationResult
    tests: TestResult
    security_scan: SecurityScanResult
    performance: PerformanceResult
    execution_time: int = 0
    overall_success: bool = False
    container_id: Optional[str] = None
    cleanup_success: bool = True
    validation_duration_ms: int = 0
    sandbox_security_notes: List[str] = Field(default_factory=list)
    sandbox_status: SandboxStatus = SandboxStatus.AVAILABLE


# ============================================================
# Validation Agent Models
# ============================================================

class ValidationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNVERIFIED = "UNVERIFIED"


class CompilationScore(BaseModel):
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="0.0 = fails, 1.0 = compiles clean")
    success: bool = False
    language: str = ""
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
    verified: bool = True


class UnitTestScore(BaseModel):
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="0.0 = all fail, 1.0 = all pass")
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    framework: str = ""
    output: str = ""
    duration_ms: int = 0
    failure_details: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None
    verified: bool = True


class RegressionScore(BaseModel):
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="0.0 = regressions found, 1.0 = no regressions")
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    regressions_found: int = 0
    regression_details: List[Dict[str, Any]] = Field(default_factory=list)
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
    verified: bool = True


class SecurityValidationScore(BaseModel):
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="0.0 = critical vulns, 1.0 = clean")
    vulnerabilities_found: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    scanner: str = "semgrep"
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
    verified: bool = True


class FunctionalBehaviorScore(BaseModel):
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="0.0 = behavior broken, 1.0 = behavior preserved")
    tests_run: int = 0
    behavior_preserved: bool = True
    output_compared: bool = False
    output_diff: str = ""
    side_effects_detected: List[str] = Field(default_factory=list)
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
    verified: bool = True


class PerformanceImpactScore(BaseModel):
    score: float = Field(default=1.0, ge=0.0, le=1.0, description="0.0 = severe regression, 1.0 = no impact")
    baseline_time_ms: int = 0
    patched_time_ms: int = 0
    time_regression_pct: float = 0.0
    baseline_memory_mb: float = 0.0
    patched_memory_mb: float = 0.0
    memory_regression_pct: float = 0.0
    within_acceptable_range: bool = True
    output: str = ""
    duration_ms: int = 0
    error: Optional[str] = None
    verified: bool = True


class PatchValidationResult(BaseModel):
    patch_id: str
    validation_id: str = ""
    vulnerability_id: str = ""
    compilation_score: CompilationScore = Field(default_factory=CompilationScore)
    unit_test_score: UnitTestScore = Field(default_factory=UnitTestScore)
    regression_score: RegressionScore = Field(default_factory=RegressionScore)
    security_score: SecurityValidationScore = Field(default_factory=SecurityValidationScore)
    functional_score: FunctionalBehaviorScore = Field(default_factory=FunctionalBehaviorScore)
    performance_score: PerformanceImpactScore = Field(default_factory=PerformanceImpactScore)
    validation_status: ValidationStatus = ValidationStatus.ERROR
    sandbox_status: SandboxStatus = SandboxStatus.AVAILABLE
    validation_duration_ms: int = 0
    created_at: str = ""


class ValidateCandidatesRequest(BaseModel):
    vulnerability_id: str
    candidates: List[PatchCandidate] = Field(default_factory=list)
    file_path: str = ""
    original_code: str = ""
    language: str = "python"
    test_command: Optional[str] = None
    regression_test_command: Optional[str] = None
    compile_command: Optional[str] = None
    scan_command: Optional[str] = None
    baseline_performance: Optional[Dict[str, Any]] = None
    sandbox_config: Optional[SandboxConfig] = None


class ValidateCandidatesResponse(BaseModel):
    vulnerability_id: str
    results: List[PatchValidationResult] = Field(default_factory=list)
    total_validated: int = 0
    passed_count: int = 0
    failed_count: int = 0
    validation_duration_ms: int = 0
    sandbox_status: SandboxStatus = SandboxStatus.AVAILABLE


# ============================================================
# Adaptive Confidence Engine Models
# ============================================================

class FeatureName(str, Enum):
    STATIC_SECURITY = "static_security"
    UNIT_TEST_SUCCESS = "unit_test_success"
    REGRESSION_SUCCESS = "regression_success"
    COMPILATION_SUCCESS = "compilation_success"
    PERFORMANCE = "performance"
    HISTORICAL_SUCCESS = "historical_success"


class FeatureScore(BaseModel):
    feature: FeatureName
    raw_value: float = Field(ge=0.0, le=1.0, description="Raw feature value 0.0-1.0")
    normalized_value: float = Field(ge=0.0, le=1.0, description="Normalized value 0.0-1.0")
    weight: float = Field(ge=0.0, le=1.0, description="Weight for this feature (0.0-1.0)")
    weighted_score: float = Field(ge=0.0, le=1.0, description="weight * normalized_value")
    evidence: str = ""
    is_penalty: bool = False
    penalty_reason: Optional[str] = None


class WeightConfig(BaseModel):
    static_security: float = Field(default=0.25, ge=0.0, le=1.0)
    unit_test_success: float = Field(default=0.20, ge=0.0, le=1.0)
    regression_success: float = Field(default=0.20, ge=0.0, le=1.0)
    compilation_success: float = Field(default=0.10, ge=0.0, le=1.0)
    performance: float = Field(default=0.10, ge=0.0, le=1.0)
    historical_success: float = Field(default=0.15, ge=0.0, le=1.0)

    def sum_weights(self) -> float:
        return (
            self.static_security
            + self.unit_test_success
            + self.regression_success
            + self.compilation_success
            + self.performance
            + self.historical_success
        )

    def to_dict(self) -> Dict[str, float]:
        return {
            "static_security": self.static_security,
            "unit_test_success": self.unit_test_success,
            "regression_success": self.regression_success,
            "compilation_success": self.compilation_success,
            "performance": self.performance,
            "historical_success": self.historical_success,
        }


class ConfidenceResult(BaseModel):
    patch_id: str
    vulnerability_id: str = ""
    confidence_score: float = Field(ge=0.0, le=100.0, description="Final confidence 0-100%")
    feature_scores: List[FeatureScore] = Field(default_factory=list)
    weights_used: WeightConfig = Field(default_factory=WeightConfig)
    positive_evidence: List[str] = Field(default_factory=list)
    negative_evidence: List[str] = Field(default_factory=list)
    validation_failures: List[str] = Field(default_factory=list)
    recommendation: str = ""
    algorithm_version: str = "v1.0"
    calculation_duration_ms: int = 0
    created_at: str = ""


class ConfidenceRanking(BaseModel):
    vulnerability_id: str
    rankings: List[ConfidenceResult] = Field(default_factory=list)
    total_patches: int = 0
    best_patch_id: Optional[str] = None
    worst_patch_id: Optional[str] = None
    weights_used: WeightConfig = Field(default_factory=WeightConfig)
    calculation_duration_ms: int = 0


class RankPatchesRequest(BaseModel):
    vulnerability_id: str
    validation_results: List[PatchValidationResult] = Field(default_factory=list)
    historical_success_rates: Optional[Dict[str, float]] = None
    weights: Optional[WeightConfig] = None
    vulnerability_type: Optional[str] = None
    patch_strategies: Optional[Dict[str, str]] = None


class RankPatchesResponse(BaseModel):
    vulnerability_id: str
    ranking: ConfidenceRanking
    calculation_duration_ms: int = 0


class ConfidenceHistoryRow(BaseModel):
    id: str = ""
    vulnerability_id: str = ""
    patch_id: str = ""
    confidence_score: float = 0.0
    feature_scores: Dict[str, float] = Field(default_factory=dict)
    weights_used: Dict[str, float] = Field(default_factory=dict)
    algorithm_version: str = "v1.0"
    created_at: str = ""


# ============================================================
# Patch Ranking & Recommendation Models
# ============================================================

class PatchRankEntry(BaseModel):
    """A single ranked patch in the recommendation output."""
    rank: int = Field(ge=1, description="Rank position (1 = best)")
    patch_id: str
    security_strategy: str = ""
    validation_status: str = ""
    confidence_score: float = Field(ge=0.0, le=100.0, description="Confidence %")
    recommendation_label: str = ""
    reasoning: str = ""
    evidence: List[str] = Field(default_factory=list)
    meets_safety_threshold: bool = False


class PatchRecommendation(BaseModel):
    """Top-level recommendation for a vulnerability."""
    vulnerability_id: str
    ranked_patches: List[PatchRankEntry] = Field(default_factory=list)
    total_patches: int = 0
    recommended_patch_id: Optional[str] = None
    recommendation_text: str = "No safe patch recommendation."
    meets_safety_threshold: bool = False
    safety_threshold: float = 50.0
    calculation_duration_ms: int = 0
    created_at: str = ""


class RecommendationResponse(BaseModel):
    """API response wrapping PatchRecommendation."""
    vulnerability_id: str
    recommendation: PatchRecommendation
    status: str = "success"


# ============================================================
# Explainable Security Recommendation Models
# ============================================================

class FeatureContribution(BaseModel):
    """Contribution of a single feature to the final confidence score."""
    feature_name: str
    weight: float = Field(ge=0.0, le=1.0)
    normalized_value: float = Field(ge=0.0, le=1.0)
    weighted_score: float = Field(ge=0.0, le=1.0)
    contribution_pct: float = Field(
        ge=0.0, le=100.0,
        description="Percentage of total confidence this feature contributes",
    )
    evidence: str = ""
    passed: bool = True


class SecurityFindingComparison(BaseModel):
    """Before/after comparison of security findings."""
    finding_type: str
    before_count: int = 0
    after_count: int = 0
    delta: int = 0
    improved: bool = False


class ExplanationChecklist(BaseModel):
    """Itemized checklist explaining why a patch is (or is not) recommended."""
    compilation_passed: bool = False
    compilation_detail: str = ""
    unit_tests_passed: bool = False
    unit_tests_detail: str = ""
    regression_tests_passed: bool = False
    regression_tests_detail: str = ""
    security_findings_reduced: bool = False
    security_detail: str = ""
    no_critical_vulnerability: bool = False
    critical_detail: str = ""
    performance_acceptable: bool = False
    performance_detail: str = ""
    historical_success_rate: bool = False
    historical_detail: str = ""


class PatchExplanation(BaseModel):
    """Full explanation for why a specific patch is recommended (or not)."""
    vulnerability_id: str = ""
    patch_id: str = ""
    confidence_score: float = Field(ge=0.0, le=100.0)
    recommendation_label: str = ""
    meets_safety_threshold: bool = False
    safety_threshold: float = 50.0
    why_this_patch: str = ""
    checklist: ExplanationChecklist = Field(default_factory=ExplanationChecklist)
    feature_contributions: List[FeatureContribution] = Field(default_factory=list)
    validation_evidence: List[str] = Field(default_factory=list)
    security_comparison: List[SecurityFindingComparison] = Field(default_factory=list)
    before_total_vulns: int = 0
    after_total_vulns: int = 0
    created_at: str = ""


class ExplanationResponse(BaseModel):
    """API response for explanation endpoint."""
    vulnerability_id: str
    patch_id: str
    explanation: PatchExplanation
    status: str = "success"


# ============================================================
# Human-in-the-Loop Patch Approval Models
# ============================================================

class ApprovalDecision(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    PENDING = "PENDING"


class PatchReviewResponse(BaseModel):
    """Full review context for a patch before approval/rejection."""
    vulnerability_id: str
    patch_id: str
    original_code: str
    patched_code: str
    diff: str
    vulnerability_type: str = ""
    vulnerability_description: str = ""
    vulnerability_severity: str = ""
    validation_results: Optional[PatchValidationResult] = None
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    explanation: Optional[PatchExplanation] = None
    security_strategy: str = ""
    created_at: str = ""


class ApprovePatchRequest(BaseModel):
    """Request to approve a patch."""
    developer_id: str = Field(..., description="ID of the developer approving")
    patch_id: str
    vulnerability_id: str
    confidence_score: float = Field(ge=0.0, le=100.0, description="Confidence at time of approval")
    vulnerability_type: str = ""
    patch_strategy: str = ""


class RejectPatchRequest(BaseModel):
    """Request to reject a patch."""
    developer_id: str = Field(..., description="ID of the developer rejecting")
    patch_id: str
    vulnerability_id: str
    reason: str = Field(default="", description="Optional reason for rejection")


class PatchApprovalRecord(BaseModel):
    """Stored approval/rejection record."""
    id: str = ""
    vulnerability_id: str
    patch_id: str
    decision: ApprovalDecision
    developer_id: str
    confidence_score: float = 0.0
    vulnerability_type: str = ""
    patch_strategy: str = ""
    rejection_reason: str = ""
    approved_at: Optional[str] = None
    rejected_at: Optional[str] = None
    created_at: str = ""


class PatchApprovalResponse(BaseModel):
    """API response after approve/reject action."""
    vulnerability_id: str
    patch_id: str
    decision: ApprovalDecision
    approval_record: PatchApprovalRecord
    message: str = ""
    status: str = "success"


# ============================================================
# Adaptive Learning Engine Models
# ============================================================

class DeploymentOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class LearningRecord(BaseModel):
    """A single learning event from developer feedback or deployment."""
    id: str = ""
    vulnerability_id: str
    patch_id: str
    vulnerability_type: str = ""
    patch_strategy: str = ""
    validation_features: Dict[str, float] = Field(default_factory=dict)
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    developer_decision: ApprovalDecision = ApprovalDecision.PENDING
    developer_id: str = ""
    rejection_reason: str = ""
    deployment_outcome: DeploymentOutcome = DeploymentOutcome.UNKNOWN
    deployment_notes: str = ""
    model_version: str = "v1.0"
    created_at: str = ""


class LearningPattern(BaseModel):
    """An extracted pattern from aggregated learning records."""
    pattern_id: str = ""
    vulnerability_type: str
    patch_strategy: str
    sample_count: int = 0
    acceptance_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    average_confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    deployment_success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    historical_weight: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_interval_lower: float = 0.0
    confidence_interval_upper: float = 1.0
    last_updated: str = ""
    model_version: str = "v1.0"


class WeightAdjustment(BaseModel):
    """Record of a scoring weight change for audit trail."""
    adjustment_id: str = ""
    previous_weights: WeightConfig = Field(default_factory=WeightConfig)
    new_weights: WeightConfig = Field(default_factory=WeightConfig)
    reason: str = ""
    patterns_used: List[str] = Field(default_factory=list)
    performance_before: float = 0.0
    performance_after: float = 0.0
    model_version: str = "v1.0"
    adjusted_by: str = "system"
    created_at: str = ""


class LearningSummary(BaseModel):
    """Summary of all learning data for a vulnerability type."""
    vulnerability_type: str
    total_records: int = 0
    acceptance_rate: float = 0.0
    average_confidence: float = 0.0
    deployment_success_rate: float = 0.0
    top_strategies: List[Dict[str, Any]] = Field(default_factory=list)
    model_version: str = "v1.0"


class LearningDashboard(BaseModel):
    """Dashboard view of all learning data."""
    total_records: int = 0
    total_patterns: int = 0
    model_version: str = "v1.0"
    overall_acceptance_rate: float = 0.0
    overall_deployment_success: float = 0.0
    patterns: List[LearningPattern] = Field(default_factory=list)
    recent_adjustments: List[WeightAdjustment] = Field(default_factory=list)


class RecordLearningRequest(BaseModel):
    """Request to record a learning event."""
    vulnerability_id: str
    patch_id: str
    vulnerability_type: str = ""
    patch_strategy: str = ""
    validation_features: Dict[str, float] = Field(default_factory=dict)
    confidence_score: float = Field(default=0.0, ge=0.0, le=100.0)
    developer_decision: ApprovalDecision = ApprovalDecision.PENDING
    developer_id: str = ""
    rejection_reason: str = ""
    deployment_outcome: DeploymentOutcome = DeploymentOutcome.UNKNOWN
    deployment_notes: str = ""


class RecordDeploymentOutcomeRequest(BaseModel):
    """Request to record post-deployment outcome."""
    vulnerability_id: str
    patch_id: str
    deployment_outcome: DeploymentOutcome
    deployment_notes: str = ""


# ============================================================
# Runtime Security Monitoring Models
# ============================================================

class RuntimeEventType(str, Enum):
    API_ANOMALY = "API_ANOMALY"
    REPEATED_SUSPICIOUS_REQUEST = "REPEATED_SUSPICIOUS_REQUEST"
    ERROR_SPIKE = "ERROR_SPIKE"
    AUTH_ANOMALY = "AUTH_ANOMALY"
    SECURITY_EVENT = "SECURITY_EVENT"
    PERFORMANCE_REGRESSION = "PERFORMANCE_REGRESSION"


class EventSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuntimeEvent(BaseModel):
    """A single runtime monitoring event."""
    event_id: str = ""
    event_type: RuntimeEventType
    severity: EventSeverity
    source: str = ""
    description: str = ""
    endpoint: str = ""
    method: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    client_ip: str = ""
    user_agent: str = ""
    request_count: int = 1
    time_window_seconds: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    detected_at: str = ""
    model_version: str = "v1.0"


class SecurityAlert(BaseModel):
    """Security alert triggered by a runtime event."""
    alert_id: str = ""
    event_id: str
    event_type: RuntimeEventType
    severity: EventSeverity
    vulnerability_type: str = ""
    vulnerability_description: str = ""
    affected_endpoint: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    recommended_action: str = ""
    triggered_reanalysis: bool = False
    patch_generated: bool = False
    patch_validated: bool = False
    developer_notified: bool = False
    created_at: str = ""


class RuntimeEventBatch(BaseModel):
    """Batch of runtime events for analysis."""
    events: List[RuntimeEvent] = Field(default_factory=list)


class MonitoringConfig(BaseModel):
    """Configuration for runtime monitoring thresholds."""
    error_rate_threshold: float = Field(default=0.1, description="Error rate threshold (0.0-1.0)")
    response_time_threshold_ms: int = Field(default=5000, description="Response time threshold in ms")
    suspicious_request_threshold: int = Field(default=10, description="Suspicious request count threshold")
    auth_failure_threshold: int = Field(default=5, description="Auth failure count threshold")
    anomaly_window_seconds: int = Field(default=300, description="Time window for anomaly detection in seconds")
    max_events_per_window: int = Field(default=100, description="Max events per time window")


class MonitoringSummary(BaseModel):
    """Summary of monitoring data for dashboard."""
    total_events: int = 0
    total_alerts: int = 0
    events_by_type: Dict[str, int] = Field(default_factory=dict)
    events_by_severity: Dict[str, int] = Field(default_factory=dict)
    alerts_by_severity: Dict[str, int] = Field(default_factory=dict)
    recent_events: List[RuntimeEvent] = Field(default_factory=list)
    recent_alerts: List[SecurityAlert] = Field(default_factory=list)
    top_anomaly_endpoints: List[Dict[str, Any]] = Field(default_factory=list)
    monitoring_config: MonitoringConfig = Field(default_factory=MonitoringConfig)
    uptime_seconds: int = 0
    last_event_at: Optional[str] = None


class SimulateEventsRequest(BaseModel):
    """Request to simulate runtime events for testing."""
    count: int = Field(default=10, ge=1, le=100, description="Number of events to simulate")
    event_types: Optional[List[RuntimeEventType]] = None
    severity_distribution: Optional[Dict[str, float]] = None


class SimulateEventsResponse(BaseModel):
    """Response after simulating events."""
    events_created: int = 0
    alerts_triggered: int = 0
    events: List[RuntimeEvent] = Field(default_factory=list)
    alerts: List[SecurityAlert] = Field(default_factory=list)


# ============================================================
# Research Experiment Framework Models
# ============================================================

class ExperimentMode(str, Enum):
    LLM_ONLY = "LLM_ONLY"
    STATIC_SCANNER = "STATIC_SCANNER"
    SINGLE_PATCH_LLM = "SINGLE_PATCH_LLM"
    MULTI_PATCH_LLM = "MULTI_PATCH_LLM"
    MULTI_PATCH_VALIDATION = "MULTI_PATCH_VALIDATION"
    HALLUCISHIELD = "HALLUCISHIELD"


class ExperimentDataSource(str, Enum):
    SIMULATION = "SIMULATION"
    REAL = "REAL"


class VulnerabilityTestCategory(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    HARDCODED_SECRETS = "HARDCODED_SECRETS"
    INSECURE_JWT = "INSECURE_JWT"
    AUTH_FLAW = "AUTH_FLAW"
    HALLUCINATED_API = "HALLUCINATED_API"
    HALLUCINATED_PACKAGE = "HALLUCINATED_PACKAGE"


class TestCase(BaseModel):
    """A single test case in the benchmark dataset."""
    test_id: str
    vuln_category: VulnerabilityTestCategory
    vulnerability_type: str
    severity: str
    file_path: str
    original_code: str
    vulnerable_line: int = 0
    description: str = ""
    cwe: str = ""
    expected_detection: bool = True
    expected_patch_types: List[str] = Field(default_factory=list)


class TestCaseRecord(BaseModel):
    """Full pipeline record for a single test case through a mode."""
    test_id: str
    vuln_category: VulnerabilityTestCategory
    vulnerability_type: str
    mode: ExperimentMode
    data_source: ExperimentDataSource = ExperimentDataSource.SIMULATION
    detection_result: bool = False
    detection_correct: bool = False
    generated_patches_count: int = 0
    validation_performed: bool = False
    best_confidence_score: float = 0.0
    selected_patch_id: str = ""
    patch_success: bool = False
    regression_detected: bool = False
    validation_time_ms: int = 0
    false_positive: bool = False
    false_negative: bool = False
    actual_scanner_result: str = ""
    actual_patches: List[str] = Field(default_factory=list)
    actual_validation_status: str = ""
    actual_patch_outcome: str = ""
    execution_time_ms: int = 0
    system_config: Dict[str, str] = Field(default_factory=dict)
    experiment_version: str = "v1.0"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExperimentConfig(BaseModel):
    """Configuration for an experiment run."""
    experiment_name: str = ""
    modes: List[ExperimentMode] = Field(
        default_factory=lambda: list(ExperimentMode)
    )
    test_categories: Optional[List[VulnerabilityTestCategory]] = None
    dataset_version: str = "v1.0"
    config_version: str = "v1.0"
    max_patches_per_test: int = 5
    validation_enabled: bool = True


class ExperimentMetrics(BaseModel):
    """Calculated metrics for a single mode."""
    mode: ExperimentMode
    total_tests: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    detection_accuracy: float = 0.0
    patch_success_rate: float = 0.0
    regression_rate: float = 0.0
    false_positive_rate: float = 0.0
    avg_validation_time_ms: float = 0.0
    confidence_calibration: float = 0.0
    total_patches_generated: int = 0
    total_patches_validated: int = 0


class ExperimentRun(BaseModel):
    """Complete experiment run with all results."""
    experiment_id: str = ""
    config: ExperimentConfig = Field(default_factory=ExperimentConfig)
    data_source: ExperimentDataSource = ExperimentDataSource.SIMULATION
    records: List[TestCaseRecord] = Field(default_factory=list)
    metrics_by_mode: Dict[str, ExperimentMetrics] = Field(default_factory=dict)
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    dataset_hash: str = ""
    status: str = "pending"


class RunExperimentRequest(BaseModel):
    """Request to run an experiment."""
    experiment_name: str = ""
    data_source: ExperimentDataSource = ExperimentDataSource.SIMULATION
    modes: Optional[List[ExperimentMode]] = None
    test_categories: Optional[List[VulnerabilityTestCategory]] = None
    max_patches_per_test: int = 5


class ExperimentSummary(BaseModel):
    """Summary of an experiment for listing."""
    experiment_id: str
    experiment_name: str
    status: str
    total_tests: int
    modes_run: int
    started_at: str
    completed_at: str
    duration_ms: int
