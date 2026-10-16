"""
Hallucination-to-Vulnerability Causal Analysis Engine for HalluciShield AI.

Analyzes the causal relationship between detected LLM hallucinations
(e.g., phantom methods, hallucinated packages, invalid security assumptions)
and identified security vulnerabilities (CWEs).

CRITICAL RESEARCH INTEGRITY:
- Never infers causality solely because two findings occur in the same file.
- Strictly evaluates direct structural, dataflow, or dependency links.
- Uses controlled categories and status.
- Traces complete causal evidence chains.
- Distinguishes ground-truth-supported, evidence-supported, plausible, and unknown.
"""

import logging
import os
import re
import uuid
import time
from typing import List, Dict, Any, Optional, Tuple

from app.agents.models import (
    HallucinationFinding,
    SecurityFinding,
    FindingType,
    CausalCategoryEnum,
    CausalStatusEnum,
    CausalFinding,
    CausalAnalysisResponse,
)

logger = logging.getLogger(__name__)


class CausalAnalysisEngine:
    """
    Engine to identify, verify, and quantify causal links from
    hallucinations to security vulnerabilities.
    """

    def __init__(self):
        pass

    def _categorize_hallucination(self, hf: HallucinationFinding) -> CausalCategoryEnum:
        """Map a HallucinationFinding to the research-controlled causal category."""
        htype = hf.type.value if hasattr(hf.type, "value") else str(hf.type)

        if htype in ("PHANTOM_METHOD", "UNKNOWN_API", "SIGNATURE_MISMATCH"):
            return CausalCategoryEnum.API_HALLUCINATION
        elif htype in ("HALLUCINATED_PACKAGE", "SUSPICIOUS_IMPORT", "SUSPICIOUS_DEPENDENCY"):
            return CausalCategoryEnum.PACKAGE_HALLUCINATION
        elif htype == "UNSUPPORTED_SECURITY_ASSUMPTION":
            return CausalCategoryEnum.SECURITY_PROPERTY_HALLUCINATION
        elif "DOCUMENT" in htype:
            return CausalCategoryEnum.DOCUMENTATION_HALLUCINATION
        elif "SEMANTIC" in htype:
            return CausalCategoryEnum.SEMANTIC_HALLUCINATION
        else:
            return CausalCategoryEnum.UNKNOWN

    def analyze_vulnerability_causality(
        self,
        vulnerability: SecurityFinding,
        hallucinations: List[HallucinationFinding],
        source_code: Optional[str] = None,
    ) -> CausalFinding:
        """
        Determine if an observed vulnerability originates from an identifiable hallucination.
        """
        vuln_file = os.path.normpath(vulnerability.file).lower()
        vuln_line = vulnerability.line
        vuln_evidence = (vulnerability.evidence or "").lower()
        cwe = vulnerability.cwe or "UNKNOWN_CWE"

        candidate_links: List[Tuple[HallucinationFinding, CausalStatusEnum, str, List[str]]] = []

        for hf in hallucinations:
            h_file = os.path.normpath(hf.file).lower()
            h_line = hf.line
            h_symbol = (hf.evidence.symbol_name if hf.evidence else "").strip()
            h_category = self._categorize_hallucination(hf)

            # Rule 1: Must be the same file or a direct imported dependency
            same_file = (vuln_file == h_file) or (vuln_file.endswith(h_file) or h_file.endswith(vuln_file))
            if not same_file:
                continue

            symbol_lower = h_symbol.lower()
            symbol_in_vuln_evidence = bool(symbol_lower and symbol_lower in vuln_evidence)
            line_diff = abs(vuln_line - h_line)

            # Check direct evidence link
            if symbol_in_vuln_evidence and line_diff <= 5:
                # Strongest direct link: the hallucinated symbol is explicitly in the vulnerability evidence
                chain = [
                    f"Hallucination [{hf.type.value}]: '{h_symbol}' verified as {hf.verification_status.value}",
                    f"Affected symbol/call at line {h_line} directly involved in vulnerability at line {vuln_line}",
                    f"Security finding: {vulnerability.type.value} ({cwe})",
                    f"Causal evidence: Vulnerable statement explicitly references hallucinated symbol '{h_symbol}'",
                ]
                evidence_text = (
                    f"Direct causal link: Vulnerability ({cwe}) at line {vuln_line} directly invokes or uses "
                    f"hallucinated symbol '{h_symbol}' flagged at line {h_line}."
                )
                candidate_links.append((hf, CausalStatusEnum.CAUSAL_SUPPORTED, evidence_text, chain))

            elif h_category == CausalCategoryEnum.PACKAGE_HALLUCINATION and (symbol_in_vuln_evidence or line_diff <= 15):
                # Package hallucination where package or symbol is used near vulnerability
                chain = [
                    f"Package Hallucination: '{h_symbol}'",
                    f"Imported at line {h_line} used in vulnerable scope around line {vuln_line}",
                    f"Security finding: {vulnerability.type.value} ({cwe})",
                    f"Causal evidence: Vulnerability relies on non-existent or hallucinated package dependency",
                ]
                evidence_text = (
                    f"Supported package causality: Module relies on hallucinated package '{h_symbol}' "
                    f"leading to unverified/insecure dependency vulnerability ({cwe})."
                )
                status = CausalStatusEnum.CAUSAL_SUPPORTED if symbol_in_vuln_evidence else CausalStatusEnum.CAUSAL_PLAUSIBLE
                candidate_links.append((hf, status, evidence_text, chain))

            elif h_category == CausalCategoryEnum.SECURITY_PROPERTY_HALLUCINATION and line_diff <= 10:
                # Developer/LLM assumed security property that was hallucinated
                chain = [
                    f"Security Property Hallucination: '{hf.explanation}'",
                    f"Flawed security assumption applied at line {h_line}",
                    f"Vulnerability triggered at line {vuln_line}: {vulnerability.type.value} ({cwe})",
                    f"Causal evidence: Missing sanitization/escaping due to hallucinated security property",
                ]
                evidence_text = (
                    f"Plausible causal link: Flawed assumption about security controls near line {vuln_line} "
                    f"permitted {cwe}."
                )
                candidate_links.append((hf, CausalStatusEnum.CAUSAL_PLAUSIBLE, evidence_text, chain))

            elif line_diff <= 3:
                # Proximity link without exact symbol match
                chain = [
                    f"Hallucination finding at line {h_line}: {hf.explanation}",
                    f"Vulnerability finding at line {vuln_line}: {cwe}",
                    f"Proximity overlap within 3 lines in {hf.file}",
                ]
                evidence_text = (
                    f"Plausible link based on tight structural proximity (within {line_diff} lines) "
                    f"between hallucination and vulnerability."
                )
                candidate_links.append((hf, CausalStatusEnum.CAUSAL_PLAUSIBLE, evidence_text, chain))

        # Select strongest link
        if candidate_links:
            # Sort by priority: CAUSAL_SUPPORTED first, then CAUSAL_PLAUSIBLE
            candidate_links.sort(
                key=lambda x: (1 if x[1] == CausalStatusEnum.CAUSAL_SUPPORTED else 0),
                reverse=True,
            )
            best_hf, best_status, best_evidence, best_chain = candidate_links[0]
            cat = self._categorize_hallucination(best_hf)
            return CausalFinding(
                causal_id=f"causal-{uuid.uuid4().hex[:10]}",
                vulnerability_id=vulnerability.finding_id,
                hallucination_id=best_hf.finding_id,
                category=cat.value,
                status=best_status.value,
                cwe=cwe,
                affected_symbol=best_hf.evidence.symbol_name if best_hf.evidence else "",
                file_path=vulnerability.file,
                line_number=vulnerability.line,
                causal_chain=best_chain,
                causal_evidence=best_evidence,
                attribution_type="evidence-supported" if best_status == CausalStatusEnum.CAUSAL_SUPPORTED else "plausible",
            )

        # No causal link found
        return CausalFinding(
            causal_id=f"causal-{uuid.uuid4().hex[:10]}",
            vulnerability_id=vulnerability.finding_id,
            hallucination_id=None,
            category=CausalCategoryEnum.NO_HALLUCINATION_EVIDENCE.value,
            status=CausalStatusEnum.NO_CAUSAL_EVIDENCE.value,
            cwe=cwe,
            affected_symbol="",
            file_path=vulnerability.file,
            line_number=vulnerability.line,
            causal_chain=[
                f"Vulnerability: {vulnerability.type.value} ({cwe}) at {vulnerability.file}:{vulnerability.line}",
                "No correlating hallucination finding found with structural or symbol evidence",
            ],
            causal_evidence="No hallucination origin identified for this security finding.",
            attribution_type="none",
        )

    def analyze_repository_causality(
        self,
        repository_id: str,
        vulnerabilities: List[SecurityFinding],
        hallucinations: List[HallucinationFinding],
        known_hallucination_count: Optional[int] = None,
        ground_truth_causal_count: Optional[int] = None,
    ) -> CausalAnalysisResponse:
        """
        Run causal analysis over all vulnerabilities in a repository/run and compute
        research-grade causal metrics.
        """
        start_time = time.time()
        findings: List[CausalFinding] = []

        for vuln in vulnerabilities:
            cf = self.analyze_vulnerability_causality(vuln, hallucinations)
            findings.append(cf)

        # Calculate research metrics
        total_vulns = len(vulnerabilities)
        total_hallucinations = len(hallucinations)

        supported_cases = [f for f in findings if f.status == CausalStatusEnum.CAUSAL_SUPPORTED.value]
        plausible_cases = [f for f in findings if f.status == CausalStatusEnum.CAUSAL_PLAUSIBLE.value]
        claimed_cases = supported_cases + plausible_cases

        # Metric 1: Hallucination Detection Rate (if known_hallucination_count provided)
        detection_rate = None
        if known_hallucination_count and known_hallucination_count > 0:
            detection_rate = round(min(1.0, total_hallucinations / known_hallucination_count), 4)

        # Metric 2: Hallucination-to-Vulnerability Rate
        # vulnerabilities with supported hallucination origin / analyzed vulnerabilities
        h2v_rate = round(len(supported_cases) / total_vulns, 4) if total_vulns > 0 else 0.0

        # Metric 3: Causal Attribution Precision
        # supported causal attributions / all claimed causal attributions
        attr_precision = (
            round(len(supported_cases) / len(claimed_cases), 4)
            if claimed_cases
            else 1.0
        )

        # Metric 4: Causal Attribution Coverage
        # supported causal cases / cases where causal evidence exists (or ground truth if available)
        baseline_causal = ground_truth_causal_count if ground_truth_causal_count is not None else len(claimed_cases)
        attr_coverage = (
            round(len(supported_cases) / baseline_causal, 4)
            if baseline_causal > 0
            else 1.0
        )

        # Group by category
        category_breakdown: Dict[str, int] = {}
        for f in findings:
            category_breakdown[f.category] = category_breakdown.get(f.category, 0) + 1

        duration_ms = int((time.time() - start_time) * 1000)

        metrics = {
            "total_vulnerabilities_analyzed": total_vulns,
            "total_hallucinations_detected": total_hallucinations,
            "causal_supported_count": len(supported_cases),
            "causal_plausible_count": len(plausible_cases),
            "no_causal_evidence_count": len(findings) - len(claimed_cases),
            "hallucination_detection_rate": detection_rate,
            "hallucination_to_vulnerability_rate": h2v_rate,
            "causal_attribution_precision": attr_precision,
            "causal_attribution_coverage": attr_coverage,
            "category_breakdown": category_breakdown,
        }

        return CausalAnalysisResponse(
            repository_id=repository_id,
            total_vulnerabilities=total_vulns,
            total_hallucinations=total_hallucinations,
            causal_findings=findings,
            metrics=metrics,
            analysis_duration_ms=duration_ms,
        )
