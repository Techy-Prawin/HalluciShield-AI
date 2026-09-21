from typing import List, Dict, Any, Tuple
from app.analyzer.models import AnalysisResult, PackageReference, FunctionSymbol, SecurityConstruct
from app.agents.models import VerificationEvidence, VerificationStatus, FindingType
from app.agents.verification_engine import DeterministicVerificationEngine


class CandidateSymbol:
    def __init__(self, symbol_type: str, name: str, file_path: str, line_number: int, context: Dict[str, Any]):
        self.symbol_type = symbol_type  # PACKAGE, METHOD, FUNCTION, SECURITY_CONSTRUCT
        self.name = name
        self.file_path = file_path
        self.line_number = line_number
        self.context = context


class EvidenceCollector:
    @classmethod
    def collect_evidence_candidates(cls, analysis_result: AnalysisResult) -> List[Tuple[CandidateSymbol, VerificationEvidence]]:
        candidates: List[Tuple[CandidateSymbol, VerificationEvidence]] = []

        # 1. Package References Verification
        for pkg in analysis_result.packages:
            evidence = DeterministicVerificationEngine.verify_package(pkg.package_name, pkg.ecosystem)
            candidate = CandidateSymbol(
                symbol_type="PACKAGE",
                name=pkg.package_name,
                file_path=pkg.file_path,
                line_number=1,
                context={"ecosystem": pkg.ecosystem, "version": pkg.version_spec}
            )
            candidates.append((candidate, evidence))

        # 2. Function & Method Symbols Verification
        for func in analysis_result.functions:
            target_module = func.class_name if func.class_name else "global"
            if "." in func.name:
                parts = func.name.split(".")
                target_module = parts[0]
                method_name = parts[1]
            else:
                method_name = func.name

            valid, evidence = DeterministicVerificationEngine.verify_method_symbol(target_module, method_name)
            candidate = CandidateSymbol(
                symbol_type="METHOD",
                name=func.name,
                file_path=func.file_path,
                line_number=func.line_number,
                context={"params": func.params, "async": func.async_def}
            )
            candidates.append((candidate, evidence))

        # 3. Security Constructs Verification
        for sec in analysis_result.security_relevant_constructs:
            code_snippet = sec.code_snippet or ""
            # Check for suspicious security assumptions (e.g. algorithm: 'none')
            if "none" in code_snippet.lower() and ("algorithm" in code_snippet.lower() or "jwt" in code_snippet.lower()):
                evidence = VerificationEvidence(
                    symbol_name="JWT_ALGORITHM_NONE",
                    check_type="SECURITY_ASSUMPTION_CHECK",
                    registry="OWASP Security Rules",
                    registry_status="UNSUPPORTED_SECURITY_ASSUMPTION",
                    facts=["JWT verification configured with algorithm 'none' allowing unsigned token bypass."],
                    raw_details={"category": sec.category, "snippet": code_snippet}
                )
                candidate = CandidateSymbol(
                    symbol_type="SECURITY_CONSTRUCT",
                    name="JWT_ALGORITHM_NONE",
                    file_path=sec.file_path,
                    line_number=sec.line_number,
                    context={"snippet": code_snippet}
                )
                candidates.append((candidate, evidence))

        return candidates
