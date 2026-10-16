"""Test suite for Phase 3.3 — Full ACE Production Pipeline Integration.

Verifies:
1. Evaluator invokes production agents.
2. HallucinationAgent is not bypassed (runs for all categories).
3. DependencyAgent is not bypassed (runs for all categories).
4. RiskEngine receives valid production schema (real agent responses).
5. PatchAgent executes when findings exist.
6. ValidationAgent executes on generated patch candidates.
7. Production ConfidenceEngine executes and computes real ACE score.
8. No inline ACE formula exists in evaluator or adapter.
9. Errors never become CLEAN (exceptions produce FAILED/NOT_RUN).
10. Ground truth never affects prediction.
"""

import inspect
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
AI_ENGINE = REPO_ROOT / "ai-engine"
if str(AI_ENGINE) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE))

from evaluation.dataset_b.full_ace_adapter import FullACEAdapter, ExecutionStatus
from evaluation.dataset_b.evaluator import run_full_ace, get_dataset_loader, load_all_samples_info
from app.agents.confidence_engine import ConfidenceEngine
from app.agents.dependency_agent import DependencyAnalysisAgent
from app.agents.hallucination_agent import HallucinationDetectionAgent
from app.agents.patch_agent import PatchGenerationAgent
from app.agents.risk_engine import RiskEngine
from app.agents.security_agent import SecurityAnalysisAgent
from app.agents.validation_agent import ValidationAgent


@pytest.fixture
def sample_vuln_py(tmp_path):
    fp = tmp_path / "vuln.py"
    fp.write_text(
        "import os\n"
        "def run_command(user_input):\n"
        "    os.system(user_input)\n",
        encoding="utf-8"
    )
    return fp


@pytest.fixture
def sample_clean_py(tmp_path):
    fp = tmp_path / "clean.py"
    fp.write_text(
        "def add(a, b):\n"
        "    return a + b\n",
        encoding="utf-8"
    )
    return fp


def test_1_evaluator_invokes_production_agents():
    """Verify adapter initializes and invokes the real production agents."""
    adapter = FullACEAdapter()
    assert isinstance(adapter.hallucination_agent, HallucinationDetectionAgent)
    assert isinstance(adapter.dependency_agent, DependencyAnalysisAgent)
    assert isinstance(adapter.security_agent, SecurityAnalysisAgent)
    assert isinstance(adapter.risk_engine, RiskEngine)
    assert isinstance(adapter.patch_agent, PatchGenerationAgent)
    assert isinstance(adapter.validation_agent, ValidationAgent)
    assert isinstance(adapter.confidence_engine, ConfidenceEngine)


def test_2_and_3_hallucination_and_dependency_not_bypassed(sample_vuln_py):
    """Verify Hallucination and Dependency agents run on all categories (no bypass)."""
    adapter = FullACEAdapter()
    sample_info = {
        "sample_id": "TEST-001",
        "category": "cwe78",
        "cwe": "CWE-78",
        "language": "python",
        "label": "positive",
    }
    result = adapter.evaluate_sample(sample_info, sample_vuln_py)
    
    assert "hallucination" in result["stages_completed"]
    assert result["stage_records"]["hallucination"]["executed"] is True
    assert result["stage_records"]["hallucination"]["status"] == ExecutionStatus.COMPLETED
    
    assert "dependency" in result["stages_completed"]
    assert result["stage_records"]["dependency"]["executed"] is True
    assert result["stage_records"]["dependency"]["status"] == ExecutionStatus.COMPLETED


def test_4_risk_engine_receives_valid_production_schema(sample_vuln_py):
    """Verify RiskEngine receives real agent responses and computes valid RiskAssessment."""
    adapter = FullACEAdapter()
    sample_info = {
        "sample_id": "TEST-002",
        "category": "cwe78",
        "cwe": "CWE-78",
        "language": "python",
        "label": "positive",
    }
    result = adapter.evaluate_sample(sample_info, sample_vuln_py)
    risk_rec = result["stage_records"]["risk"]
    
    assert risk_rec["executed"] is True
    assert risk_rec["status"] == ExecutionStatus.COMPLETED
    assert risk_rec["output_type"] == "RiskAssessment"
    assert isinstance(risk_rec["overall_risk_score"], (int, float))
    assert risk_rec["overall_risk_level"] in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_5_6_7_patch_validation_and_confidence_execute_on_findings(sample_vuln_py):
    """Verify PatchAgent, ValidationAgent, and ConfidenceEngine execute when vulnerabilities are found."""
    adapter = FullACEAdapter()
    sample_info = {
        "sample_id": "TEST-003",
        "category": "cwe78",
        "cwe": "CWE-78",
        "language": "python",
        "label": "positive",
    }
    result = adapter.evaluate_sample(sample_info, sample_vuln_py)
    
    # Patch stage
    patch_rec = result["stage_records"]["patch"]
    assert patch_rec["executed"] is True
    assert patch_rec["status"] == ExecutionStatus.COMPLETED
    assert patch_rec["candidate_count"] > 0
    
    # Validation stage
    val_rec = result["stage_records"]["validation"]
    assert val_rec["executed"] is True
    assert val_rec["status"] == ExecutionStatus.COMPLETED
    assert val_rec["validation_status"] in ["PASS", "FAIL", "WARNING"]
    
    # Confidence stage
    conf_rec = result["stage_records"]["confidence"]
    assert conf_rec["executed"] is True
    assert conf_rec["status"] == ExecutionStatus.COMPLETED
    assert isinstance(conf_rec["ace_score"], (int, float))
    assert 0.0 <= conf_rec["ace_score"] <= 100.0
    assert "static_security" in conf_rec["f1_to_f6"]


def test_8_no_inline_ace_formula_exists():
    """Verify evaluator and adapter do NOT contain inline heuristic ACE proxy formulas."""
    import evaluation.dataset_b.full_ace_adapter as fa_module
    import evaluation.dataset_b.evaluator as ev_module
    
    fa_source = inspect.getsource(fa_module)
    ev_source = inspect.getsource(ev_module)
    
    # Check for legacy proxy formula
    assert "f1_static = min(100.0" not in fa_source
    assert "f1_static = min(100.0" not in ev_source
    assert "deterministic proxy" not in fa_source.lower()
    assert "deterministic proxy" not in ev_source.lower()


def test_9_errors_never_become_clean(tmp_path):
    """Verify that any unhandled exception in detection produces FAILED, never CLEAN (negative)."""
    adapter = FullACEAdapter()
    # Mock SecurityAnalysisAgent to throw an error
    adapter.security_agent.analyze_security = MagicMock(side_effect=RuntimeError("Simulated scanner crash"))
    
    test_fp = tmp_path / "test.py"
    test_fp.write_text("print('hello')", encoding="utf-8")
    
    sample_info = {
        "sample_id": "TEST-ERR",
        "category": "cwe78",
        "cwe": "CWE-78",
        "language": "python",
        "label": "positive",
    }
    result = adapter.evaluate_sample(sample_info, test_fp)
    
    assert result["scanner_status"] == ExecutionStatus.FAILED
    assert result["predicted_label"] == ExecutionStatus.FAILED
    assert result["predicted_label"] != "negative"
    assert result["detection_correct"] is None


def test_10_ground_truth_never_affects_prediction(sample_clean_py):
    """Verify prediction is determined by actual evidence, not sample label."""
    adapter = FullACEAdapter()
    
    # Provide identical clean code with label="positive" vs label="negative"
    info_pos = {"sample_id": "T1", "category": "clean", "cwe": "NONE", "language": "python", "label": "positive"}
    info_neg = {"sample_id": "T2", "category": "clean", "cwe": "NONE", "language": "python", "label": "negative"}
    
    res_pos = adapter.evaluate_sample(info_pos, sample_clean_py)
    res_neg = adapter.evaluate_sample(info_neg, sample_clean_py)
    
    # Both must reach the same predicted label because code is identical
    assert res_pos["predicted_label"] == res_neg["predicted_label"] == "negative"
