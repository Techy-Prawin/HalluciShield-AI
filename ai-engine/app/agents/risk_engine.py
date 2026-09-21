"""
Risk Assessment Engine for HalluciShield AI.

Combines findings from all analysis agents to produce a deterministic,
explainable repository-level risk score.

Scoring Logic (Deterministic):
- Each category (hallucination, security, dependency) contributes a weighted risk score
- Category scores are calculated based on finding counts and severity weights
- Overall risk is a weighted average of category scores
- No LLM involvement in numerical scoring
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from app.agents.models import (
    HallucinationFinding,
    SecurityFinding,
    DependencyFinding,
    DetectionResponse,
    SecurityAnalysisResponse,
    DependencyAnalysisResponse,
    RiskAssessment,
    RiskAssessmentRequest,
    CategoryRisk,
    RiskLevel,
)

logger = logging.getLogger(__name__)


class RiskScoringConfig:
    """Deterministic configuration for risk scoring."""
    
    # Severity weights for calculating category risk scores
    SEVERITY_WEIGHTS = {
        "CRITICAL": 25.0,
        "HIGH": 15.0,
        "MEDIUM": 8.0,
        "LOW": 3.0,
    }
    
    # Maximum possible score per finding (capped at 100)
    MAX_CATEGORY_SCORE = 100.0
    
    # Category weights for overall risk calculation
    CATEGORY_WEIGHTS = {
        "hallucination": 0.40,  # Hallucinations are most critical
        "security": 0.35,       # Security vulnerabilities are second priority
        "dependency": 0.25,     # Dependency issues are third priority
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        RiskLevel.CRITICAL: 80.0,
        RiskLevel.HIGH: 60.0,
        RiskLevel.MEDIUM: 40.0,
        RiskLevel.LOW: 20.0,
        RiskLevel.INFO: 0.0,
    }
    
    # Maximum findings to include in top_issues
    MAX_TOP_ISSUES = 5


class RiskEngine:
    """
    Deterministic risk assessment engine that combines findings from
    hallucination, security, and dependency analysis agents.
    
    All scoring is deterministic and explainable - no LLM involvement.
    """
    
    def __init__(self, config: Optional[RiskScoringConfig] = None):
        self.config = config or RiskScoringConfig()
    
    def calculate_category_risk(
        self,
        category: str,
        findings: List[Any],
    ) -> CategoryRisk:
        """
        Calculate risk score for a single category.
        
        Args:
            category: Category name (hallucination, security, dependency)
            findings: List of findings for this category
            
        Returns:
            CategoryRisk with calculated score and breakdown
        """
        total_findings = len(findings)
        
        if total_findings == 0:
            return CategoryRisk(
                category=category,
                risk_score=0.0,
                total_findings=0,
                top_issues=[],
            )
        
        # Count by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for finding in findings:
            severity = self._get_severity(finding)
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            elif severity == "LOW":
                low_count += 1
        
        # Calculate weighted score
        raw_score = (
            critical_count * self.config.SEVERITY_WEIGHTS["CRITICAL"] +
            high_count * self.config.SEVERITY_WEIGHTS["HIGH"] +
            medium_count * self.config.SEVERITY_WEIGHTS["MEDIUM"] +
            low_count * self.config.SEVERITY_WEIGHTS["LOW"]
        )
        
        # Cap at maximum score
        risk_score = min(raw_score, self.config.MAX_CATEGORY_SCORE)
        
        # Get top issues (sorted by severity, then confidence)
        top_issues = self._get_top_issues(findings)
        
        return CategoryRisk(
            category=category,
            risk_score=risk_score,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            top_issues=top_issues,
        )
    
    def calculate_overall_risk(
        self,
        hallucination_risk: CategoryRisk,
        security_risk: CategoryRisk,
        dependency_risk: CategoryRisk,
    ) -> tuple[float, RiskLevel, List[Dict[str, Any]]]:
        """
        Calculate overall risk score from category risks.
        
        Returns:
            Tuple of (risk_score, risk_level, risk_factors)
        """
        # Weighted average
        overall_score = (
            hallucination_risk.risk_score * self.config.CATEGORY_WEIGHTS["hallucination"] +
            security_risk.risk_score * self.config.CATEGORY_WEIGHTS["security"] +
            dependency_risk.risk_score * self.config.CATEGORY_WEIGHTS["dependency"]
        )
        
        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(
            hallucination_risk, security_risk, dependency_risk
        )
        
        return overall_score, risk_level, risk_factors
    
    def generate_recommendations(
        self,
        hallucination_risk: CategoryRisk,
        security_risk: CategoryRisk,
        dependency_risk: CategoryRisk,
        overall_risk_level: RiskLevel,
    ) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        # Hallucination recommendations
        if hallucination_risk.critical_count > 0:
            recommendations.append(
                f"URGENT: {hallucination_risk.critical_count} critical hallucinated packages detected. "
                "Verify all package imports against official registries before deployment."
            )
        elif hallucination_risk.high_count > 0:
            recommendations.append(
                f"Review {hallucination_risk.high_count} high-confidence hallucinated packages. "
                "These may cause runtime failures."
            )
        
        # Security recommendations
        if security_risk.critical_count > 0:
            recommendations.append(
                f"URGENT: {security_risk.critical_count} critical security vulnerabilities found. "
                "Address immediately to prevent potential exploits."
            )
        elif security_risk.high_count > 0:
            recommendations.append(
                f"Fix {security_risk.high_count} high-severity security issues. "
                "Review OWASP guidelines for remediation."
            )
        
        # Dependency recommendations
        if dependency_risk.critical_count > 0:
            recommendations.append(
                f"URGENT: {dependency_risk.critical_count} critical dependency issues. "
                "Check for hallucinated or malicious packages."
            )
        if dependency_risk.high_count > 0:
            recommendations.append(
                f"Review {dependency_risk.high_count} dependency warnings. "
                "Update or remove unused/suspicious dependencies."
            )
        
        # Overall recommendations
        if overall_risk_level == RiskLevel.CRITICAL:
            recommendations.append(
                "Repository has CRITICAL risk level. "
                "Consider blocking deployment until all critical issues are resolved."
            )
        elif overall_risk_level == RiskLevel.HIGH:
            recommendations.append(
                "Repository has HIGH risk level. "
                "Review and address high-priority findings before deployment."
            )
        
        if not recommendations:
            recommendations.append("No critical issues detected. Continue monitoring.")
        
        return recommendations
    
    def assess_risk(
        self,
        repository_id: str,
        hallucination_response: DetectionResponse,
        security_response: SecurityAnalysisResponse,
        dependency_response: DependencyAnalysisResponse,
    ) -> RiskAssessment:
        """
        Main method to assess repository risk from all agent findings.
        
        Args:
            repository_id: Unique repository identifier
            hallucination_response: Findings from hallucination detection
            security_response: Findings from security analysis
            dependency_response: Findings from dependency analysis
            
        Returns:
            Complete RiskAssessment with scores and recommendations
        """
        logger.info(f"[RiskEngine] Calculating risk for repository: {repository_id}")
        
        # Calculate category risks
        hallucination_risk = self.calculate_category_risk(
            "hallucination",
            hallucination_response.findings,
        )
        
        security_risk = self.calculate_category_risk(
            "security",
            security_response.findings,
        )
        
        dependency_risk = self.calculate_category_risk(
            "dependency",
            dependency_response.findings,
        )
        
        # Calculate overall risk
        overall_score, risk_level, risk_factors = self.calculate_overall_risk(
            hallucination_risk, security_risk, dependency_risk
        )
        
        # Generate recommendations
        recommendations = self.generate_recommendations(
            hallucination_risk, security_risk, dependency_risk, risk_level
        )
        
        # Calculate totals
        total_findings = (
            hallucination_risk.total_findings +
            security_risk.total_findings +
            dependency_risk.total_findings
        )
        
        critical_findings = (
            hallucination_risk.critical_count +
            security_risk.critical_count +
            dependency_risk.critical_count
        )
        
        high_findings = (
            hallucination_risk.high_count +
            security_risk.high_count +
            dependency_risk.high_count
        )
        
        medium_findings = (
            hallucination_risk.medium_count +
            security_risk.medium_count +
            dependency_risk.medium_count
        )
        
        low_findings = (
            hallucination_risk.low_count +
            security_risk.low_count +
            dependency_risk.low_count
        )
        
        assessment = RiskAssessment(
            repository_id=repository_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            overall_risk_score=overall_score,
            overall_risk_level=risk_level,
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            hallucination_risk=hallucination_risk,
            security_risk=security_risk,
            dependency_risk=dependency_risk,
            risk_factors=risk_factors,
            recommendations=recommendations,
        )
        
        logger.info(
            f"[RiskEngine] Risk assessment complete: "
            f"Score={overall_score:.1f}, Level={risk_level.value}, "
            f"Total={total_findings}, Critical={critical_findings}"
        )
        
        return assessment
    
    def _get_severity(self, finding: Any) -> str:
        """Extract severity string from any finding type."""
        if hasattr(finding, 'severity'):
            severity = finding.severity
            if hasattr(severity, 'value'):
                return severity.value
            return str(severity)
        return "LOW"
    
    def _get_top_issues(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Get top issues sorted by severity weight and confidence."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        
        def sort_key(finding):
            severity = self._get_severity(finding)
            severity_rank = severity_order.get(severity, 4)
            confidence = getattr(finding, 'confidence', 0.5)
            return (severity_rank, -confidence)
        
        sorted_findings = sorted(findings, key=sort_key)
        top_findings = sorted_findings[:self.config.MAX_TOP_ISSUES]
        
        issues = []
        for finding in top_findings:
            issue = {
                "finding_id": getattr(finding, 'finding_id', 'unknown'),
                "severity": self._get_severity(finding),
                "description": getattr(finding, 'description', 
                    getattr(finding, 'explanation', 'No description')),
                "file": getattr(finding, 'file', 'unknown'),
                "line": getattr(finding, 'line', 0),
            }
            issues.append(issue)
        
        return issues
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score using thresholds."""
        for level, threshold in sorted(
            self.config.RISK_THRESHOLDS.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if score >= threshold:
                return level
        return RiskLevel.INFO
    
    def _identify_risk_factors(
        self,
        hallucination_risk: CategoryRisk,
        security_risk: CategoryRisk,
        dependency_risk: CategoryRisk,
    ) -> List[Dict[str, Any]]:
        """Identify key risk factors contributing to overall score."""
        factors = []
        
        # Check for high-risk categories
        if hallucination_risk.risk_score > 50:
            factors.append({
                "factor": "High hallucination rate",
                "category": "hallucination",
                "score": hallucination_risk.risk_score,
                "description": f"{hallucination_risk.total_findings} hallucinated packages detected",
            })
        
        if security_risk.risk_score > 50:
            factors.append({
                "factor": "Security vulnerabilities present",
                "category": "security",
                "score": security_risk.risk_score,
                "description": f"{security_risk.total_findings} security issues found",
            })
        
        if dependency_risk.risk_score > 50:
            factors.append({
                "factor": "Dependency issues detected",
                "category": "dependency",
                "score": dependency_risk.risk_score,
                "description": f"{dependency_risk.total_findings} dependency problems found",
            })
        
        # Check for critical findings
        total_critical = (
            hallucination_risk.critical_count +
            security_risk.critical_count +
            dependency_risk.critical_count
        )
        if total_critical > 0:
            factors.append({
                "factor": "Critical findings present",
                "category": "overall",
                "score": total_critical * 25,
                "description": f"{total_critical} critical issues require immediate attention",
            })
        
        return factors
