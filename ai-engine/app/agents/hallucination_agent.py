import time
import uuid
import logging
from typing import List
from app.analyzer.engine import RepositoryAnalyzer
from app.agents.models import DetectionResponse, HallucinationFinding, VerificationStatus
from app.agents.evidence_collector import EvidenceCollector
from app.agents.llm_reasoner import LLMReasoner

logger = logging.getLogger(__name__)


class HallucinationDetectionAgent:
    """
    Adaptive Multi-Agent Hallucination Detection Agent
    Investigates repository source code for hallucinated packages, phantom methods,
    suspicious imports, unknown APIs, signature mismatches, and unsupported security assumptions.
    
    Multi-stage pipeline:
    1. Static Extraction - Parse codebase to extract symbols
    2. Deterministic Verification - Verify against known registries/symbol tables
    3. Evidence Collection - Gather evidence for each candidate
    4. LLM Reasoning - Use LLM to analyze evidence (with deterministic fallback)
    5. Hallucination Finding - Compile structured findings with confidence scores
    """

    def __init__(self):
        self.analyzer = RepositoryAnalyzer()

    def detect_hallucinations(self, repository_id: str, workspace_path: str) -> DetectionResponse:
        """
        Main detection pipeline that processes a repository and returns hallucination findings.
        
        Args:
            repository_id: Unique identifier for the repository
            workspace_path: Path to the repository workspace
            
        Returns:
            DetectionResponse with structured findings
        """
        logger.info(f"[HallucinationAgent] Initiating detection for repository ID: {repository_id}")
        start_time = time.time()

        try:
            # Stage 1: Static Extraction
            analysis_result = self.analyzer.analyze_repository(repository_id, workspace_path)
            logger.info(f"[HallucinationAgent] Static extraction complete. Found {len(analysis_result.packages)} packages, {len(analysis_result.functions)} functions")

            # Stage 2 & 3: Deterministic Verification & Evidence Collection
            candidates = EvidenceCollector.collect_evidence_candidates(analysis_result)
            logger.info(f"[HallucinationAgent] Evidence collection complete. Generated {len(candidates)} candidates")

            findings: List[HallucinationFinding] = []
            confirmed_count = 0
            likely_count = 0
            suspicious_count = 0

            # Stage 4 & 5: LLM Reasoning & Hallucination Finding Compilation
            for idx, (candidate, evidence) in enumerate(candidates, 1):
                finding_id = f"find-{uuid.uuid4().hex[:8]}"

                try:
                    finding = LLMReasoner.evaluate_finding(
                        finding_id=finding_id,
                        symbol_type=candidate.symbol_type,
                        symbol_name=candidate.name,
                        file_path=candidate.file_path,
                        line_number=candidate.line_number,
                        evidence=evidence,
                    )

                    if finding:
                        findings.append(finding)
                        if finding.verification_status == VerificationStatus.CONFIRMED:
                            confirmed_count += 1
                        elif finding.verification_status == VerificationStatus.LIKELY:
                            likely_count += 1
                        elif finding.verification_status == VerificationStatus.SUSPICIOUS:
                            suspicious_count += 1
                except Exception as eval_err:
                    logger.warning(f"[HallucinationAgent] Error evaluating candidate {candidate.name}: {eval_err}")
                    continue

        except Exception as e:
            logger.error(f"[HallucinationAgent] Detection failed for {repository_id}: {e}", exc_info=True)
            raise

        duration_ms = int((time.time() - start_time) * 1000)
        logger.info(
            f"[HallucinationAgent] Completed detection for {repository_id} in {duration_ms}ms. "
            f"Total findings: {len(findings)} (Confirmed: {confirmed_count}, Likely: {likely_count}, Suspicious: {suspicious_count})"
        )

        return DetectionResponse(
            repository_id=repository_id,
            total_findings=len(findings),
            confirmed_findings_count=confirmed_count,
            likely_findings_count=likely_count,
            suspicious_findings_count=suspicious_count,
            findings=findings,
            analysis_duration_ms=duration_ms,
        )
