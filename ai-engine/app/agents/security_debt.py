"""
Security Debt Metric Calculator for HalluciShield AI.

Calculates technical security debt:
    SecurityDebt = Σ(severity × exposure)

Uses the project's existing severity representation from RiskScoringConfig:
    CRITICAL = 25.0
    HIGH     = 15.0
    MEDIUM   = 8.0
    LOW      = 3.0

Exposure factor:
    1.0 for standard production code / sinks
    0.5 for test/internal code or secondary sinks
    Defaults to 1.0 if not specified.

If severity is missing/invalid, explicitly marks status as NOT_AVAILABLE.
"""

from typing import List, Dict, Any, Optional, Union
from app.agents.risk_engine import RiskScoringConfig
from app.agents.models import SecurityDebtResult, SecurityFinding


def calculate_finding_debt(finding: Union[SecurityFinding, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Calculate debt for an individual finding.
    Returns None if severity is not available.
    """
    if isinstance(finding, dict):
        sev_raw = finding.get("severity")
        fid = finding.get("finding_id", "unknown")
        exposure = float(finding.get("exposure", 1.0))
        file_path = finding.get("file", "")
    else:
        sev_raw = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        fid = finding.finding_id
        exposure = float(finding.metadata.get("exposure", 1.0)) if finding.metadata else 1.0
        file_path = finding.file

    if not sev_raw or not isinstance(sev_raw, str):
        return None

    sev_clean = sev_raw.upper().strip()
    if sev_clean not in RiskScoringConfig.SEVERITY_WEIGHTS:
        return None

    weight = RiskScoringConfig.SEVERITY_WEIGHTS[sev_clean]
    debt = weight * exposure

    return {
        "finding_id": fid,
        "severity": sev_clean,
        "severity_weight": weight,
        "exposure": exposure,
        "debt": round(debt, 2),
        "file": file_path,
    }


def calculate_security_debt(
    findings_before: List[Union[SecurityFinding, Dict[str, Any]]],
    findings_after: Optional[List[Union[SecurityFinding, Dict[str, Any]]]] = None,
) -> SecurityDebtResult:
    """
    Calculate security debt before and after remediation, along with reduction.
    If severity is unavailable for all findings or missing, returns NOT_AVAILABLE.
    """
    if not findings_before and findings_after is None:
        return SecurityDebtResult(
            security_debt_before=0.0,
            security_debt_after=0.0,
            security_debt_reduction=0.0,
            reduction_pct=0.0,
            findings_debt=[],
            status="AVAILABLE",
        )

    # Calculate before debt
    debts_before = []
    has_unavailable = False

    for f in findings_before:
        d = calculate_finding_debt(f)
        if d is None:
            has_unavailable = True
        else:
            debts_before.append(d)

    # If any required severity was completely missing/unrecognized, flag or mark NOT_AVAILABLE
    if findings_before and not debts_before:
        return SecurityDebtResult(
            security_debt_before=None,
            security_debt_after=None,
            security_debt_reduction=None,
            reduction_pct=None,
            findings_debt=[],
            status="NOT_AVAILABLE",
        )

    debt_before_total = sum(d["debt"] for d in debts_before)

    if findings_after is None:
        return SecurityDebtResult(
            security_debt_before=round(debt_before_total, 2),
            security_debt_after=None,
            security_debt_reduction=None,
            reduction_pct=None,
            findings_debt=debts_before,
            status="AVAILABLE",
        )

    debts_after = []
    for f in findings_after:
        d = calculate_finding_debt(f)
        if d is not None:
            debts_after.append(d)

    debt_after_total = sum(d["debt"] for d in debts_after)
    reduction = max(0.0, debt_before_total - debt_after_total)
    reduction_pct = (reduction / debt_before_total * 100.0) if debt_before_total > 0 else 0.0

    return SecurityDebtResult(
        security_debt_before=round(debt_before_total, 2),
        security_debt_after=round(debt_after_total, 2),
        security_debt_reduction=round(reduction, 2),
        reduction_pct=round(reduction_pct, 2),
        findings_debt=debts_before,
        status="AVAILABLE",
    )
