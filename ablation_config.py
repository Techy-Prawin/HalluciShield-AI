#!/usr/bin/env python3
"""
Ablation Configuration for FullACEAdapter.

Provides explicit per-component switches for the real production pipeline.
Production default: ALL ENABLED.
"""

from pathlib import Path
from typing import Dict, List, Any, Optional


class PipelineConfig:
    """Configuration for ablating components in the Full HalluciShield ACE pipeline."""
    
    def __init__(self, 
                 hallucination_detection: bool = True,
                 dependency_analysis: bool = True,
                 security_analysis: bool = True,
                 risk_assessment: bool = True,
                 patch_generation: bool = True,
                 validation: bool = True,
                 legacy_ace: bool = True,
                 aece: bool = True,
                 multi_patch: bool = True):
        self.hallucination_detection = hallucination_detection
        self.dependency_analysis = dependency_analysis
        self.security_analysis = security_analysis
        self.risk_assessment = risk_assessment
        self.patch_generation = patch_generation
        self.validation = validation
        self.legacy_ace = legacy_ace
        self.aece = aece
        self.multi_patch = multi_patch
    
    @property
    def all_enabled(self) -> bool:
        return (self.hallucination_detection and self.dependency_analysis and 
                self.security_analysis and self.risk_assessment and self.patch_generation and
                self.validation and self.legacy_ace and self.aece and self.multi_patch)
    
    def to_dict(self) -> Dict[str, bool]:
        return {
            "hallucination_detection": self.hallucination_detection,
            "dependency_analysis": self.dependency_analysis,
            "security_analysis": self.security_analysis,
            "risk_assessment": self.risk_assessment,
            "patch_generation": self.patch_generation,
            "validation": self.validation,
            "legacy_ace": self.legacy_ace,
            "aece": self.aece,
            "multi_patch": self.multi_patch,
        }
    
    @classmethod
    def from_dict(cls, d: Dict[str, bool]) -> "PipelineConfig":
        return cls(
            hallucination_detection=d.get("hallucination_detection", True),
            dependency_analysis=d.get("dependency_analysis", True),
            security_analysis=d.get("security_analysis", True),
            risk_assessment=d.get("risk_assessment", True),
            patch_generation=d.get("patch_generation", True),
            validation=d.get("validation", True),
            legacy_ace=d.get("legacy_ace", True),
            aece=d.get("aece", True),
            multi_patch=d.get("multi_patch", True),
        )


# Production default - all enabled
PRODUCTION_CONFIG = PipelineConfig()


# ── Ablation Reason Recording ──────────────────────────────────────────────

class AblationReason:
    """Records why a stage was not executed."""
    
    def __init__(self, component: str, status: str = "NOT_APPLICABLE", 
                 reason: str = ""):
        self.component = component
        self.status = status
        self.reason = reason
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "component": self.component,
            "status": self.status,
            "reason": self.reason,
        }
    
    @classmethod
    def not_applicable(cls, component: str, reason: str = "") -> "AblationReason":
        return cls(component=component, status="NOT_APPLICABLE", reason=reason)


# ── Provenance-Evidence Helpers ───────────────────────────────────────────

def make_not_available_provenance(component: str) -> Dict[str, Dict[str, str]]:
    """Create evidence_status entry for a NOT_AVAILABLE component."""
    return {
        component: {
            "status": "NOT_AVAILABLE",
            "provenance": "NOT_APPLICABLE",
        }
    }


# ── FullACEAdapter Refactoring ──────────────────────────────────────────

# The FullACEAdapter needs to be refactored to accept a PipelineConfig
# and use it to conditionally execute stages.

# Example conceptual flow after refactoring:
#
# adapter = FullACEAdapter(config=PipelineConfig(hallucination_detection=False))
# result = adapter.evaluate_sample(sample_info, file_path)
#
# When hallucination_detection=False:
#   - HallucinationAgent is not executed
#   - hallucination evidence = NOT_APPLICABLE with provenance NOT_APPLICABLE
#   - Downstream stages continue using normal inputs
#   - No fabricated hallucination result

# When dependency_analysis=False:
#   - DependencyAnalysisAgent is not executed
#   - dependency evidence = NOT_APPLICABLE with provenance NOT_APPLICABLE
#   - Security continues only if its real API permits missing dependency evidence
#   - Otherwise explicitly return NOT_APPLICABLE, never fabricate

# Production default (ALL ENABLED) must produce equivalent outputs/schema/statuses
# to the current unconfigured evaluate_sample method.