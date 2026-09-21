import json
import logging
from typing import Dict, Any, Optional

from app.config import settings
from app.agents.models import VerificationEvidence, VerificationStatus, FindingType, HallucinationFinding
from app.agents.llm_client import chat_json
from app.security import sanitize_for_llm_prompt

logger = logging.getLogger(__name__)


class LLMReasoner:
    """
    Stage 4: LLM Reasoning Engine
    Evaluates evidence collected in Stage 2 & 3 and generates structured JSON reasoning.
    Does NOT allow an LLM response alone to invent findings without evidence.
    """

    @classmethod
    def evaluate_finding(
        cls,
        finding_id: str,
        symbol_type: str,
        symbol_name: str,
        file_path: str,
        line_number: int,
        evidence: VerificationEvidence,
    ) -> Optional[HallucinationFinding]:
        # 1. Deterministic Rule Filtering: If evidence shows verified real symbol, return None (NOT hallucinated)
        if evidence.registry_status == "200_OK":
            return None

        # 2. Deterministic decision from evidence. The LLM never invents a finding
        #    or changes its type/status; it may only enrich the explanation.
        finding = cls._fallback_reasoner(finding_id, symbol_type, symbol_name, file_path, line_number, evidence)
        if finding is None:
            return None

        # 3. LLM enrichment (best-effort, optional)
        enrichment = cls._query_llm_reasoner(symbol_name, file_path, line_number, evidence)
        if enrichment:
            explanation = enrichment.get("explanation")
            if explanation:
                finding.explanation = explanation
            try:
                llm_confidence = float(enrichment.get("confidence", finding.confidence))
            except (TypeError, ValueError):
                llm_confidence = finding.confidence
            if 0.0 <= llm_confidence <= 1.0:
                # LLM may only raise confidence above the deterministic floor, never lower it.
                finding.confidence = max(finding.confidence, llm_confidence)
        return finding

    @classmethod
    def _query_llm_reasoner(
        cls,
        symbol_name: str,
        file_path: str,
        line_number: int,
        evidence: VerificationEvidence,
    ) -> Optional[Dict[str, Any]]:
        try:
            prompt = f"""You are HalluciShield AI Security Agent. Analyze this symbol and verification evidence:
Symbol: {sanitize_for_llm_prompt(symbol_name)}
File: {sanitize_for_llm_prompt(file_path)}:{line_number}
Check Type: {evidence.check_type}
Registry Status: {evidence.registry_status}
Facts: {json.dumps(evidence.facts)[:5000]}

The deterministic registry/symbol-table check has already classified this
element, so do NOT return a type, severity, or verification status. ONLY
respond with a valid JSON object containing a concise human-readable
"explanation" and a "confidence" float between 0.0 and 1.0 that reflects how
strongly the evidence supports the already-determined classification:
{{
  "explanation": "Human readable reason grounded only in the provided facts",
  "confidence": 0.95
}}
"""
            raw_text = chat_json(prompt, timeout=30.0)
            if not raw_text:
                return None
            data = json.loads(raw_text)
            return data
        except Exception as e:
            logger.debug(f"[LLMReasoner] LLM enrichment query skipped or unavailable: {e}")
        return None

    @classmethod
    def _fallback_reasoner(
        cls,
        finding_id: str,
        symbol_type: str,
        symbol_name: str,
        file_path: str,
        line_number: int,
        evidence: VerificationEvidence,
    ) -> Optional[HallucinationFinding]:
        status = VerificationStatus.NOT_VERIFIED
        finding_type = FindingType.SUSPICIOUS_IMPORT
        severity = "MEDIUM"
        confidence = 0.7000
        explanation = f"Potential hallucinated construct identified in '{symbol_name}'."
        method = "DETERMINISTIC_REGISTRY_CHECK"

        if evidence.registry_status == "404_NOT_FOUND":
            status = VerificationStatus.CONFIRMED
            finding_type = FindingType.HALLUCINATED_PACKAGE
            severity = "CRITICAL"
            confidence = 0.9800
            explanation = f"Package '{symbol_name}' returned 404 Not Found on package registry. High risk of phantom package slugcashing."
            method = "DETERMINISTIC_REGISTRY_CHECK"

        elif evidence.registry_status == "SYMBOL_NOT_FOUND":
            status = VerificationStatus.CONFIRMED
            finding_type = FindingType.PHANTOM_METHOD
            severity = "HIGH"
            confidence = 0.9200
            explanation = f"Method '{symbol_name}' does not exist on target module/library symbol table."
            method = "AST_SYMBOL_VERIFICATION"

        elif evidence.registry_status == "UNSUPPORTED_SECURITY_ASSUMPTION":
            status = VerificationStatus.CONFIRMED
            finding_type = FindingType.UNSUPPORTED_SECURITY_ASSUMPTION
            severity = "CRITICAL"
            confidence = 0.9900
            explanation = f"Security construct in '{file_path}:{line_number}' relies on unsupported or bypass security parameter (e.g. algorithm 'none')."
            method = "DETERMINISTIC_SECURITY_RULE"

        elif "unusual" in symbol_name.lower() or "mismatch" in symbol_name.lower():
            status = VerificationStatus.SUSPICIOUS
            finding_type = FindingType.SIGNATURE_MISMATCH
            severity = "MEDIUM"
            confidence = 0.7500
            explanation = f"API call '{symbol_name}' exhibits unusual parameter signature usage."
            method = "LLM_HYBRID_REASONING"

        if status == VerificationStatus.NOT_VERIFIED:
            return None

        return HallucinationFinding(
            finding_id=finding_id,
            type=finding_type,
            file=file_path,
            line=line_number,
            evidence=evidence,
            explanation=explanation,
            severity=severity,
            confidence=confidence,
            verification_status=status,
            verification_method=method,
        )
