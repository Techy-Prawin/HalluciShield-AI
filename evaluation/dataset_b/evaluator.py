#!/usr/bin/env python3
"""Dataset B Full ACE Evaluation - Phase 3 (REPAIRED).

Evaluates four independent systems on the same 500 Dataset B records:
  A. Semgrep-only baseline
  B. LLM zero-shot baseline
  C. Sandbox baseline
  D. Full HalluciShield + ACE

REPAIR LOG (Phase 3.2):
  Bug 1 FIXED: Semgrep — fallback scanner os.walk(file) → now single-file scan
  Bug 2 FIXED: LLM — API call moved inside for-loop; each sample is independently processed
  Bug 3 FIXED: Sandbox — language-aware execution; no-oracle → NOT_APPLICABLE; never CLEAN on error
  Bug 4 FIXED: Full ACE — uses real production agents (security/hallucination/dependency/
                risk/patch/validation/confidence_engine); no invented orchestration module
  Bug 5 FIXED: Metrics isolation — each system computes and stores its own cm/metrics
  Bug 6 FIXED: main() key name — "full_ace_baseline" replaced with "full_ace"
  Bug 7 FIXED: Error→negative — all failure modes now use explicit FAILED/NOT_RUN/NOT_APPLICABLE

STATUS MODEL:
  COMPLETED       — detection logic ran and produced a definitive prediction
  FAILED          — detection logic threw an error; prediction is indeterminate
  NOT_RUN         — conditions (API key, binary) for this system were not met
  NOT_APPLICABLE  — the oracle/technique cannot apply to this sample
  TIMEOUT         — system exceeded time limit
"""

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Repo root / sys.path ─────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
_AI_ENGINE = _REPO_ROOT / "ai-engine"
if str(_AI_ENGINE) not in sys.path:
    sys.path.insert(0, str(_AI_ENGINE))

try:
    from dotenv import load_dotenv
    load_dotenv(_REPO_ROOT / ".env")
except ImportError:
    pass


# ── Dataset B paths ──────────────────────────────────────────────────────────
METADATA_CSV    = _REPO_ROOT / "dataset" / "dataset-b" / "metadata.csv"
MANIFEST_JSON   = _REPO_ROOT / "dataset" / "dataset-b" / "MANIFEST.json"
DATASET_FILES_ROOT = _REPO_ROOT / "dataset" / "dataset" / "dataset-b"

# ── Experiment metadata ──────────────────────────────────────────────────────
EXPERIMENT_NAME    = "phase-3-dataset-b-ace-evaluation"
EXPERIMENT_VERSION = "v2.0"          # bumped for repaired evaluator
TIMESTAMP          = datetime.now(timezone.utc).isoformat()

MANIFEST_HASH = hashlib.sha256(
    open(MANIFEST_JSON, "rb").read()
).hexdigest()[:16]

with open(MANIFEST_JSON, "r", encoding="utf-8") as _f:
    MANIFEST = json.load(_f)
MANIFEST_BY_ID = {s["sample_id"]: s for s in MANIFEST["samples"]}

# ── Dataset loader ───────────────────────────────────────────────────────────
from evaluation.dataset_b.dataset_loader import DatasetBLoader

_dataset_loader: Optional[DatasetBLoader] = None


def get_dataset_loader() -> DatasetBLoader:
    global _dataset_loader
    if _dataset_loader is None:
        _dataset_loader = DatasetBLoader(
            metadata_csv=METADATA_CSV,
            files_root=DATASET_FILES_ROOT,
        )
    return _dataset_loader


# ── Status constants ─────────────────────────────────────────────────────────
class ExecutionStatus:
    COMPLETED      = "COMPLETED"
    FAILED         = "FAILED"
    NOT_RUN        = "NOT_RUN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    TIMEOUT        = "TIMEOUT"


# ── Sample helpers ───────────────────────────────────────────────────────────

def compute_record_id(file_path: str, disk_sha256: str) -> str:
    return hashlib.sha256(
        (file_path + ":" + disk_sha256).encode("utf-8")
    ).hexdigest()


def get_sample_info(sample: Dict) -> Dict:
    sample_id  = sample["sample_id"]
    file_path  = sample["file_path"]
    label      = sample["label"]
    cwe        = sample["cwe"]
    category   = sample["category"]
    language   = sample["language"]
    generator_model = sample.get("generator_model", "")
    ground_truth    = sample.get("ground_truth", "")

    manifest_rec    = MANIFEST_BY_ID.get(sample_id, {})
    disk_sha256     = manifest_rec.get("disk_sha256", "MISSING")
    metadata_sha256 = sample.get("sha256", "MISSING").lower()

    if disk_sha256 == "MISSING":
        try:
            loader = get_dataset_loader()
            fp = loader.get_file_path(sample)
            if fp.exists():
                disk_sha256 = hashlib.sha256(open(fp, "rb").read()).hexdigest().lower()
        except Exception:
            pass

    rid = compute_record_id(file_path, disk_sha256)
    return {
        "sample_id":      sample_id,
        "record_id":      rid,
        "file_path":      file_path,
        "language":       language,
        "category":       category,
        "cwe":            cwe,
        "label":          label,
        "ground_truth":   ground_truth,
        "generator_model": generator_model,
        "metadata_sha256": metadata_sha256,
        "disk_sha256":    disk_sha256,
        "manifest_rec":   manifest_rec,
    }


def load_all_samples_info() -> List[Dict]:
    loader = get_dataset_loader()
    rows   = loader.get_samples()
    return [get_sample_info(r) for r in rows]


# ── Ground-truth helpers ─────────────────────────────────────────────────────

def _ground_truth_cm(detected: bool, label: str) -> Dict:
    """Compute one-sample confusion matrix cells from detected flag and label."""
    detection_correct = (detected and label == "positive") or (
        not detected and label == "negative"
    )
    false_positive = detected and label == "negative"
    false_negative = not detected and label == "positive"
    return {
        "detection_correct": detection_correct,
        "false_positive":    false_positive,
        "false_negative":    false_negative,
        "predicted_label":   "positive" if detected else "negative",
    }


# ============================================================================
# A. Semgrep-only baseline  (REPAIRED)
# ============================================================================

def _semgrep_scan_single_file(fp: Path, sample_id: str) -> Tuple[List, Dict]:
    """
    Run the SecurityAnalysisAgent on a single source file.

    FIX Bug 1: The previous code passed a file path to SecurityAnalysisAgent
    and the fallback scanner used os.walk(file) which yields zero iterations.
    The real fix is to write the file into a dedicated temp directory so the
    scanner can walk that directory and find the file.
    """
    from app.agents.security_agent import SecurityAnalysisAgent

    agent = SecurityAnalysisAgent()

    # Write the file into an isolated temp directory
    with tempfile.TemporaryDirectory(prefix=f"hs_semgrep_{sample_id}_") as tmp_dir:
        # Preserve the original filename so extension-based filtering works
        dest = Path(tmp_dir) / fp.name
        shutil.copy2(fp, dest)

        try:
            response = agent.analyze_security(
                repository_id=f"semgrep-{sample_id}",
                workspace_path=tmp_dir,          # directory, not file
            )
            findings   = response.findings
            scanner_meta = {
                "total_vulnerabilities": response.total_vulnerabilities,
                "critical_count":        response.critical_count,
                "high_count":            response.high_count,
                "medium_count":          response.medium_count,
                "low_count":             response.low_count,
                "scanner":               "semgrep_or_fallback",
                "workspace":             tmp_dir,
            }
            return findings, scanner_meta
        except Exception as e:
            raise RuntimeError(f"SecurityAnalysisAgent failed: {e}") from e


def run_semgrep_baseline(samples_info: List[Dict]) -> Dict[str, Any]:
    """
    Semgrep-only baseline — REPAIRED.

    Fixes:
      - Passes a temp directory (not a raw file path) to the agent
      - scanner failure → FAILED (never negative)
      - Records semgrep binary availability, scan command, findings, exit code
    """
    import shutil as _shutil
    semgrep_binary = _shutil.which("semgrep")

    results = []

    for info in samples_info:
        sample_id  = info["sample_id"]
        file_path  = info["file_path"]
        label      = info["label"]
        category   = info["category"]
        cwe        = info["cwe"]
        language   = info["language"]
        ground_truth = info["ground_truth"]

        loader = get_dataset_loader()
        fp     = loader.get_file_path(info)

        detected        = False
        finding_count   = 0
        finding_types   = []
        scanner_status  = ExecutionStatus.NOT_RUN
        error_message   = None
        scanner_meta    = {}

        if not fp.exists() or fp.stat().st_size == 0:
            scanner_status = ExecutionStatus.FAILED
            error_message  = f"File not found or empty: {fp}"
        else:
            try:
                findings, scanner_meta = _semgrep_scan_single_file(fp, sample_id)
                detected      = len(findings) > 0
                finding_count = len(findings)
                finding_types = [f.type.value for f in findings]
                scanner_status = ExecutionStatus.COMPLETED
            except Exception as e:
                scanner_status = ExecutionStatus.FAILED
                error_message  = str(e)
                # NEVER map scanner failure to detected=False/predicted=negative
                # Leave detected as INDETERMINATE — use scanner_status=FAILED

        # Only set predicted_label when scanner actually completed
        if scanner_status == ExecutionStatus.COMPLETED:
            cm = _ground_truth_cm(detected, label)
        else:
            # Cannot make a prediction; record FAILED status explicitly
            cm = {
                "detection_correct": None,
                "false_positive":    None,
                "false_negative":    None,
                "predicted_label":   ExecutionStatus.FAILED,
            }

        record = {
            "record_id":        info["record_id"],
            "sample_id":        sample_id,
            "file_path":        file_path,
            "language":         language,
            "category":         category,
            "cwe":              cwe,
            "label":            label,
            "ground_truth":     ground_truth,
            "predicted_label":  cm["predicted_label"],
            "scanner_status":   scanner_status,
            "detection_correct": cm["detection_correct"],
            "false_positive":   cm["false_positive"],
            "false_negative":   cm["false_negative"],
            "finding_count":    finding_count,
            "finding_types":    finding_types,
            "error_message":    error_message,
            "semgrep_binary":   semgrep_binary,
            "scanner_meta":     scanner_meta,
            "experiment_name":  EXPERIMENT_NAME,
            "experiment_version": EXPERIMENT_VERSION,
            "timestamp":        TIMESTAMP,
            "data_source":      "semgrep_baseline",
        }
        results.append(record)

    return {"baseline": "semgrep", "results": results, "count": len(results)}


# ============================================================================
# B. LLM zero-shot baseline  (REPAIRED)
# ============================================================================

_LLM_DETECTION_PROMPT_VERSION = "v2.0-no-groundtruth"
_LLM_DETECTION_PROMPT_TEMPLATE = """\
You are a security code reviewer. Analyze the following {language} code and determine \
whether it contains a security vulnerability.

Return ONLY a JSON object, no markdown, no extra text:
{{
  "vulnerability_detected": true or false,
  "cwe": "CWE-XXX" or "NONE",
  "category": "brief category name",
  "line": <integer or null>,
  "description": "one-sentence explanation",
  "severity": "HIGH" or "MEDIUM" or "LOW" or "NONE"
}}

Code to analyze:
```
{code}
```
"""
# NOTE: The prompt does NOT include ground-truth label, CWE, category, or any
# hint from the dataset — those would contaminate the zero-shot measurement.


def run_llm_zero_shot_baseline(samples_info: List[Dict]) -> Dict[str, Any]:
    """
    LLM zero-shot baseline — REPAIRED.

    Fixes:
      - API call + response parsing + results.append are ALL inside the for-loop
      - 500 samples are attempted independently
      - Missing API key → scanner_status=NOT_RUN (never negative prediction)
      - API error → scanner_status=FAILED (never negative prediction)
      - JSON parse error → scanner_status=FAILED (never negative prediction)
      - Ground truth labels are NOT included in the prompt
    """
    import httpx

    GROQ_API_KEY  = os.getenv("LLM_API_KEY", "") or os.getenv("GROQ_API_KEY", "")
    GROQ_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
    MODEL         = os.getenv("DEFAULT_LLM_MODEL", "qwen/qwen3.8-27b")
    api_url       = f"{GROQ_BASE_URL.rstrip('/')}/chat/completions"

    results = []

    for info in samples_info:                          # ← LOOP START
        sample_id  = info["sample_id"]
        file_path  = info["file_path"]
        label      = info["label"]
        category   = info["category"]
        cwe        = info["cwe"]
        language   = info["language"]
        ground_truth = info["ground_truth"]

        # Read code
        loader = get_dataset_loader()
        fp     = loader.get_file_path(info)
        code   = ""
        if fp.exists():
            try:
                code = open(fp, encoding="utf-8", errors="replace").read()
            except Exception:
                code = ""

        # Build prompt — NO ground-truth leakage
        prompt = _LLM_DETECTION_PROMPT_TEMPLATE.format(
            language=language,
            code=code[:8000],  # truncate very long files
        )

        detected          = False
        predicted_cwe     = "NONE"
        predicted_category = "unknown"
        scanner_status    = ExecutionStatus.NOT_RUN
        error_message     = None
        latency_ms        = 0
        raw_response      = ""

        if not GROQ_API_KEY:                           # ← NO KEY → NOT_RUN
            scanner_status = ExecutionStatus.NOT_RUN
            error_message  = "LLM_API_KEY not set"
        else:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type":  "application/json",
            }
            payload = {
                "model":       MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "stream":      False,
                "temperature": 0.1,
                "top_p":       0.95,
                "max_tokens":  512,
            }
            try:
                start = time.time()
                with httpx.Client(timeout=60.0) as client:
                    resp = client.post(api_url, json=payload, headers=headers)
                latency_ms = int((time.time() - start) * 1000)

                if resp.status_code == 200:
                    data        = resp.json()
                    raw_response = (
                        data.get("choices", [{}])[0]
                            .get("message", {})
                            .get("content", "")
                            .strip()
                    )
                    try:
                        result = json.loads(raw_response)
                        detected           = bool(result.get("vulnerability_detected", False))
                        predicted_cwe      = result.get("cwe", "NONE")
                        predicted_category = result.get("category", "unknown")
                        scanner_status     = ExecutionStatus.COMPLETED
                    except (json.JSONDecodeError, ValueError) as je:
                        scanner_status = ExecutionStatus.FAILED
                        error_message  = f"JSON parse error: {je} | raw={raw_response[:200]}"
                else:
                    scanner_status = ExecutionStatus.FAILED
                    error_message  = f"HTTP {resp.status_code}: {resp.text[:200]}"

            except httpx.TimeoutException:
                scanner_status = ExecutionStatus.TIMEOUT
                error_message  = "Request timed out (60s)"
            except Exception as e:
                scanner_status = ExecutionStatus.FAILED
                error_message  = str(e)

        # Confusion matrix only if we have a definitive prediction
        if scanner_status == ExecutionStatus.COMPLETED:
            cm = _ground_truth_cm(detected, label)
        else:
            cm = {
                "detection_correct": None,
                "false_positive":    None,
                "false_negative":    None,
                "predicted_label":   scanner_status,   # FAILED / NOT_RUN / TIMEOUT
            }

        record = {
            "record_id":          info["record_id"],
            "sample_id":          sample_id,
            "file_path":          file_path,
            "language":           language,
            "category":           category,
            "cwe":                cwe,
            "label":              label,
            "ground_truth":       ground_truth,
            "predicted_label":    cm["predicted_label"],
            "scanner_status":     scanner_status,
            "detection_correct":  cm["detection_correct"],
            "false_positive":     cm["false_positive"],
            "false_negative":     cm["false_negative"],
            "latency_ms":         latency_ms,
            "error_message":      error_message,
            "model_provider":     "groq",
            "exact_model":        MODEL,
            "temperature":        0.1,
            "top_p":              0.95,
            "max_tokens":         512,
            "prompt_version":     _LLM_DETECTION_PROMPT_VERSION,
            "raw_response":       raw_response[:500] if raw_response else "",
            "predicted_cwe":      predicted_cwe,
            "predicted_category": predicted_category,
            "experiment_name":    EXPERIMENT_NAME,
            "experiment_version": EXPERIMENT_VERSION,
            "timestamp":          TIMESTAMP,
            "data_source":        "llm_zero_shot",
        }
        results.append(record)              # ← append INSIDE loop
    # ← LOOP END

    return {"baseline": "llm_zero_shot", "results": results, "count": len(results)}


# ============================================================================
# C. Sandbox baseline  (REPAIRED)
# ============================================================================

# Language → executor mapping.
# Only Python can be directly executed here without a full language runtime.
# Go/Java/JS/TS require external runtimes that are not guaranteed to be present.
_SANDBOX_SUPPORTED_LANGUAGES = {"python"}

# Vulnerability oracle definition:
# For an execution-based sandbox to produce a valid vulnerability prediction,
# it needs an EXPLICIT oracle — a test harness that exercises the vulnerable
# code path and observes a security-relevant outcome.
# Dataset B samples are standalone code snippets, NOT executable programs with
# harnesses. Running them directly cannot produce security-meaningful output.
# Therefore the sandbox baseline is NOT_APPLICABLE for all Dataset B samples.
# This is documented here and flagged per-sample in the results.
SANDBOX_ORACLE_STATUS = "NOT_APPLICABLE"
SANDBOX_ORACLE_REASON = (
    "Dataset B samples are standalone code snippets without execution harnesses. "
    "A valid sandbox oracle requires: (1) a driver that exercises the vulnerable code "
    "path with adversarial input, (2) an assertion that detects the security-relevant "
    "outcome (e.g. tainted SQL executed, shell command injected). Without (1) and (2), "
    "running code and inspecting stdout/stderr cannot distinguish vulnerable from safe code."
)


def _detect_language_executor(language: str, fp: Path) -> Optional[str]:
    """
    Return the executor command prefix for a supported language, or None.
    Checks that the executor binary is actually available.
    """
    if language == "python":
        return sys.executable
    # Future: add node, java, go as optional executors
    return None


def run_sandbox_baseline(samples_info: List[Dict]) -> Dict[str, Any]:
    """
    Sandbox baseline — REPAIRED.

    Fixes:
      - Does NOT run Go/Java/JS/TS code as Python
      - Documents that no legitimate vulnerability oracle exists for these snippets
      - All samples are marked NOT_APPLICABLE with an explicit reason
      - Language mismatch → NOT_APPLICABLE, never negative prediction
      - Execution error → FAILED, never negative prediction
    """
    results = []

    for info in samples_info:
        sample_id  = info["sample_id"]
        file_path  = info["file_path"]
        label      = info["label"]
        category   = info["category"]
        cwe        = info["cwe"]
        language   = info["language"]
        ground_truth = info["ground_truth"]

        loader = get_dataset_loader()
        fp     = loader.get_file_path(info)

        scanner_status  = ExecutionStatus.NOT_APPLICABLE
        execution_status = ExecutionStatus.NOT_APPLICABLE
        error_message   = None
        runtime_evidence = None
        latency_ms      = 0
        oracle_triggered = False
        executor        = None

        if not fp.exists():
            scanner_status   = ExecutionStatus.FAILED
            execution_status = ExecutionStatus.FAILED
            error_message    = f"File not found: {fp}"
        else:
            executor = _detect_language_executor(language, fp)
            if executor is None:
                # Unsupported language — cannot safely execute
                scanner_status   = ExecutionStatus.NOT_APPLICABLE
                execution_status = ExecutionStatus.NOT_APPLICABLE
                error_message    = (
                    f"No executor available for language '{language}'. "
                    "Sandbox only supports Python on this host."
                )
            else:
                # Even for Python: no oracle → NOT_APPLICABLE
                # Document this explicitly rather than pretending execution = detection
                scanner_status   = ExecutionStatus.NOT_APPLICABLE
                execution_status = ExecutionStatus.NOT_APPLICABLE
                error_message    = SANDBOX_ORACLE_REASON

        # Sandbox NEVER produces a binary positive/negative prediction
        # because no oracle exists. All results are NOT_APPLICABLE.
        record = {
            "record_id":          info["record_id"],
            "sample_id":          sample_id,
            "file_path":          file_path,
            "language":           language,
            "category":           category,
            "cwe":                cwe,
            "label":              label,
            "ground_truth":       ground_truth,
            "predicted_label":    ExecutionStatus.NOT_APPLICABLE,
            "scanner_status":     scanner_status,
            "execution_status":   execution_status,
            "detection_correct":  None,
            "false_positive":     None,
            "false_negative":     None,
            "latency_ms":         latency_ms,
            "timeout":            False,
            "error_message":      error_message,
            "executor":           executor,
            "oracle_triggered":   oracle_triggered,
            "oracle_status":      SANDBOX_ORACLE_STATUS,
            "oracle_reason":      SANDBOX_ORACLE_REASON,
            "runtime_evidence":   runtime_evidence,
            "experiment_name":    EXPERIMENT_NAME,
            "experiment_version": EXPERIMENT_VERSION,
            "timestamp":          TIMESTAMP,
            "data_source":        "sandbox_baseline",
        }
        results.append(record)

    return {"baseline": "sandbox", "results": results, "count": len(results)}


# ============================================================================
# D. Full HalluciShield + ACE  (REPAIRED)
# ============================================================================

# ============================================================================
# D. Full HalluciShield + ACE  (Real Production Multi-Agent Pipeline)
# ============================================================================

def run_full_ace(samples_info: List[Dict]) -> Dict[str, Any]:
    """
    Full HalluciShield + ACE — Genuine Production Pipeline.

    Uses FullACEAdapter to execute the genuine production pipeline for each sample:
      Dataset B sample
      → HallucinationDetectionAgent
      → DependencyAnalysisAgent
      → SecurityAnalysisAgent
      → RiskEngine
      → PatchGenerationAgent
      → ValidationAgent
      → ConfidenceEngine (ACE)
      → Final security decision

    No category shortcuts, no mock/stub objects, no proxy formula.
    """
    from evaluation.dataset_b.full_ace_adapter import FullACEAdapter

    adapter = FullACEAdapter()
    results = []

    for info in samples_info:
        loader = get_dataset_loader()
        fp = loader.get_file_path(info)
        record = adapter.evaluate_sample(info, fp)
        record["timestamp"] = TIMESTAMP
        results.append(record)

    return {"baseline": "full_ace", "results": results, "count": len(results)}


# ============================================================================
# Metrics  (REPAIRED — per-system isolation)
# ============================================================================

def compute_confusion_matrix(records: List[Dict]) -> Dict[str, int]:
    """
    Compute TP, FP, TN, FN.

    Only records with predicted_label in {positive, negative} contribute.
    Records with FAILED/NOT_RUN/NOT_APPLICABLE are excluded from the CM
    to avoid inflating TN or FN counts.
    """
    valid = [r for r in records if r.get("predicted_label") in ("positive", "negative")]
    tp = sum(1 for r in valid if r["detection_correct"] and r["predicted_label"] == "positive")
    fp = sum(1 for r in valid if r["false_positive"])
    tn = sum(1 for r in valid if r["detection_correct"] and r["predicted_label"] == "negative")
    fn = sum(1 for r in valid if r["false_negative"])
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def compute_execution_counts(records: List[Dict]) -> Dict[str, int]:
    """Count per-status execution totals for a system's records."""
    statuses = [r.get("scanner_status", ExecutionStatus.NOT_RUN) for r in records]
    cnt = Counter(statuses)
    return {
        "attempted":       len(records),
        "completed":       cnt.get(ExecutionStatus.COMPLETED, 0),
        "failed":          cnt.get(ExecutionStatus.FAILED, 0),
        "not_run":         cnt.get(ExecutionStatus.NOT_RUN, 0),
        "not_applicable":  cnt.get(ExecutionStatus.NOT_APPLICABLE, 0),
        "timeout":         cnt.get(ExecutionStatus.TIMEOUT, 0),
    }


def compute_metrics(tp: int, fp: int, fn: int, tn: int, total_attempted: int = 0) -> Dict[str, float]:
    valid = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    accuracy  = (tp + tn) / valid if valid > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr       = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    coverage  = valid / total_attempted if total_attempted > 0 else (1.0 if valid > 0 else 0.0)
    return {
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
        "accuracy":  round(accuracy, 4),
        "fpr":       round(fpr, 4),
        "fnr":       round(fnr, 4),
        "coverage":  round(coverage, 4),
    }


def compute_group_metrics(results: List[Dict], group_key: str) -> Dict[str, Dict]:
    """Compute per-group (CWE, category, language) confusion matrix and metrics."""
    groups: Dict[str, List[Dict]] = {}
    for r in results:
        val = r.get(group_key) or "unknown"
        groups.setdefault(val, []).append(r)
    group_stats = {}
    for g_val, recs in sorted(groups.items()):
        cm = compute_confusion_matrix(recs)
        m = compute_metrics(cm["tp"], cm["fp"], cm["fn"], cm["tn"], total_attempted=len(recs))
        exec_c = compute_execution_counts(recs)
        group_stats[g_val] = {
            "total_samples": len(recs),
            "confusion_matrix": cm,
            "metrics": m,
            "execution_counts": exec_c,
        }
    return group_stats


def compute_latency_stats(results: List[Dict]) -> Dict[str, float]:
    """Calculate mean, median, min, max latency across records."""
    import statistics
    latencies = [
        float(r.get("execution_time_ms") or r.get("latency_ms") or 0.0)
        for r in results
        if (r.get("execution_time_ms") or r.get("latency_ms")) is not None
    ]
    if not latencies:
        return {"mean_ms": 0.0, "median_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
    return {
        "mean_ms": round(statistics.mean(latencies), 2),
        "median_ms": round(statistics.median(latencies), 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
    }


def compute_confidence_stats(results: List[Dict]) -> Dict[str, Any]:
    """Calculate statistical distribution of ACE confidence scores."""
    import statistics
    scores = [float(r["ace_score"]) for r in results if r.get("ace_score") is not None]
    if not scores:
        return {"count": 0, "mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0, "std": 0.0}
    std = round(statistics.stdev(scores), 2) if len(scores) > 1 else 0.0
    return {
        "count": len(scores),
        "mean": round(statistics.mean(scores), 2),
        "median": round(statistics.median(scores), 2),
        "min": round(min(scores), 2),
        "max": round(max(scores), 2),
        "std": std,
    }


def _compute_system_metrics(results: List[Dict]) -> Tuple[Dict, Dict]:
    """Compute confusion matrix + metrics for one system's results."""
    cm = compute_confusion_matrix(results)
    m  = compute_metrics(**cm, total_attempted=len(results))
    return cm, m


# ============================================================================
# Main experiment runner  (REPAIRED)
# ============================================================================

def select_dry_run_samples(all_samples: List[Dict], count: int = 10) -> List[Dict]:
    """Select a balanced set of samples across positive/negative labels, CWE categories, and languages."""
    pos_samples = [s for s in all_samples if s["label"] == "positive"]
    neg_samples = [s for s in all_samples if s["label"] == "negative"]

    n_pos = count // 2
    n_neg = count - n_pos

    target_cats = ["cwe79", "cwe78", "cwe89", "cwe798", "cwe22", "cwe347"]
    selected_pos = []
    seen_cats = set()
    for cat in target_cats:
        for s in pos_samples:
            if s["category"] == cat and s not in selected_pos and len(selected_pos) < n_pos:
                selected_pos.append(s)
                seen_cats.add(cat)
                break
    for s in pos_samples:
        if len(selected_pos) < n_pos and s not in selected_pos:
            selected_pos.append(s)

    target_langs = ["python", "javascript", "typescript", "go", "java"]
    selected_neg = []
    seen_langs = set()
    for lang in target_langs:
        for s in neg_samples:
            if s["language"] == lang and s not in selected_neg and len(selected_neg) < n_neg:
                selected_neg.append(s)
                seen_langs.add(lang)
                break
    for s in neg_samples:
        if len(selected_neg) < n_neg and s not in selected_neg:
            selected_neg.append(s)

    return selected_pos + selected_neg


def run_all_four_experiments(sample_limit: Optional[int] = None, is_dry_run: bool = False) -> Dict[str, Any]:
    print("=" * 70)
    print("Dataset B Full ACE Evaluation - Phase 3 (REPAIRED)")
    print("=" * 70)
    print(f"Experiment: {EXPERIMENT_NAME} {EXPERIMENT_VERSION}")
    print(f"Timestamp:  {TIMESTAMP}")
    print(f"Manifest hash: {MANIFEST_HASH}")
    print()

    all_samples = load_all_samples_info()
    print(f"Loaded {len(all_samples)} samples from Dataset B")
    pos = sum(1 for s in all_samples if s["label"] == "positive")
    neg = sum(1 for s in all_samples if s["label"] == "negative")
    print(f"  Positive: {pos}  Negative: {neg}  Total: {pos+neg}")
    assert pos == 387 and neg == 113 and (pos + neg) == 500, (
        f"Dataset integrity check FAILED: pos={pos} neg={neg} total={pos+neg}"
    )
    print("  Dataset integrity: PASS")
    print()

    if is_dry_run:
        count = sample_limit or 10
        samples_info = select_dry_run_samples(all_samples, count=count)
        print(f"  [DRY-RUN MODE]: Selected {len(samples_info)} balanced samples across languages/labels")
        print()
    elif sample_limit is not None and sample_limit > 0:
        samples_info = all_samples[:sample_limit]
        print(f"  [SUBSET MODE]: Evaluating first {len(samples_info)} samples")
        print()
    else:
        samples_info = all_samples

    # ── A. Semgrep ────────────────────────────────────────────────────────────
    print("[A] Running Semgrep-only baseline...")
    semgrep_result = run_semgrep_baseline(samples_info)
    sem_cm, sem_m  = _compute_system_metrics(semgrep_result["results"])   # FIX Bug 5
    sem_exec       = compute_execution_counts(semgrep_result["results"])
    print(f"  Processed: {semgrep_result['count']} samples")
    print(f"  Execution: {sem_exec}")
    print(f"  CM (valid only): TP={sem_cm['tp']} FP={sem_cm['fp']} TN={sem_cm['tn']} FN={sem_cm['fn']}")
    print()

    # ── B. LLM ───────────────────────────────────────────────────────────────
    print("[B] Running LLM zero-shot baseline...")
    llm_result    = run_llm_zero_shot_baseline(samples_info)
    llm_cm, llm_m = _compute_system_metrics(llm_result["results"])        # FIX Bug 5
    llm_exec      = compute_execution_counts(llm_result["results"])
    print(f"  Processed: {llm_result['count']} samples")
    print(f"  Execution: {llm_exec}")
    print(f"  CM (valid only): TP={llm_cm['tp']} FP={llm_cm['fp']} TN={llm_cm['tn']} FN={llm_cm['fn']}")
    print()

    # ── C. Sandbox ────────────────────────────────────────────────────────────
    print("[C] Running Sandbox baseline...")
    sandbox_result    = run_sandbox_baseline(samples_info)
    sandbox_cm, sandbox_m = _compute_system_metrics(sandbox_result["results"])   # FIX Bug 5
    sandbox_exec          = compute_execution_counts(sandbox_result["results"])
    print(f"  Processed: {sandbox_result['count']} samples")
    print(f"  Execution: {sandbox_exec}")
    print(f"  CM (valid only): TP={sandbox_cm['tp']} FP={sandbox_cm['fp']} TN={sandbox_cm['tn']} FN={sandbox_cm['fn']}")
    print(f"  Oracle status: {SANDBOX_ORACLE_STATUS}")
    print()

    # ── D. Full ACE ───────────────────────────────────────────────────────────
    print("[D] Running Full HalluciShield + ACE...")
    ace_result    = run_full_ace(samples_info)
    ace_cm, ace_m = _compute_system_metrics(ace_result["results"])         # FIX Bug 5
    ace_exec      = compute_execution_counts(ace_result["results"])
    print(f"  Processed: {ace_result['count']} samples")
    print(f"  Execution: {ace_exec}")
    print(f"  CM (valid only): TP={ace_cm['tp']} FP={ace_cm['fp']} TN={ace_cm['tn']} FN={ace_cm['fn']}")
    print()

    # ── Build final results with per-system metrics ───────────────────────────
    final_results = {
        "experiment_name":    EXPERIMENT_NAME,
        "experiment_version": EXPERIMENT_VERSION,
        "timestamp":          TIMESTAMP,
        "dataset": {
            "total_records":    len(samples_info),
            "positive_samples": sum(1 for s in samples_info if s["label"] == "positive"),
            "negative_samples": sum(1 for s in samples_info if s["label"] == "negative"),
            "manifest_hash":    MANIFEST_HASH,
        },
        # Each system stores its OWN cm and metrics (FIX Bug 5)
        "semgrep_baseline": {
            "results":          semgrep_result["results"],
            "metrics":          sem_m,
            "confusion_matrix": sem_cm,
            "execution_counts": sem_exec,
        },
        "llm_zero_shot_baseline": {
            "results":          llm_result["results"],
            "metrics":          llm_m,
            "confusion_matrix": llm_cm,
            "execution_counts": llm_exec,
        },
        "sandbox_baseline": {
            "results":          sandbox_result["results"],
            "metrics":          sandbox_m,
            "confusion_matrix": sandbox_cm,
            "execution_counts": sandbox_exec,
            "oracle_status":    SANDBOX_ORACLE_STATUS,
            "oracle_reason":    SANDBOX_ORACLE_REASON,
        },
        "full_ace": {                                         # FIX Bug 6 (was "full_ace_baseline")
            "results":          ace_result["results"],
            "metrics":          ace_m,
            "confusion_matrix": ace_cm,
            "execution_counts": ace_exec,
        },
    }

    # Assertion: all four systems are independent (FIX Bug 5 assertion)
    assert final_results["semgrep_baseline"]["metrics"] is not final_results["llm_zero_shot_baseline"]["metrics"]
    assert final_results["semgrep_baseline"]["confusion_matrix"] is not final_results["full_ace"]["confusion_matrix"]

    return final_results


def save_results(final_results: Dict[str, Any], output_dir: Path = None) -> Dict[str, Path]:
    """Save all raw results, per-system metrics, breakdowns, and README to disk."""
    if output_dir is None:
        output_dir = _REPO_ROOT / "evaluation" / "results" / "dataset_b" / "phase3_full_ace"
    output_dir.mkdir(parents=True, exist_ok=True)

    saved_files = {}

    key_map = {
        "semgrep":       "semgrep_baseline",
        "llm_zero_shot": "llm_zero_shot_baseline",
        "sandbox":       "sandbox_baseline",
        "full_ace":      "full_ace",
    }

    category_metrics = {}
    language_metrics = {}
    latencies = {}
    confidence_stats = {}

    for system_name, fr_key in key_map.items():
        system_dir = output_dir / system_name
        system_dir.mkdir(parents=True, exist_ok=True)

        results = final_results[fr_key]["results"]

        raw_path = system_dir / "raw_results.jsonl"
        with open(raw_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, default=str) + "\n")
        saved_files[f"{system_name}_raw"] = raw_path

        system_lat = compute_latency_stats(results)
        latencies[system_name] = system_lat

        system_cm = final_results[fr_key]["confusion_matrix"]
        system_m = final_results[fr_key]["metrics"]
        system_exec = final_results[fr_key].get("execution_counts", {})

        metrics_payload = {
            "metrics":          system_m,
            "confusion_matrix": system_cm,
            "execution_counts": system_exec,
            "latency":          system_lat,
        }
        if system_name == "full_ace":
            c_stats = compute_confidence_stats(results)
            confidence_stats = c_stats
            metrics_payload["confidence_statistics"] = c_stats

        metrics_path = system_dir / "metrics.json"
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics_payload, f, indent=2)
        saved_files[f"{system_name}_metrics"] = metrics_path

        category_metrics[system_name] = compute_group_metrics(results, "category")
        language_metrics[system_name] = compute_group_metrics(results, "language")

    # Save consolidated raw_results.jsonl at output_dir root
    combined_raw_path = output_dir / "raw_results.jsonl"
    with open(combined_raw_path, "w", encoding="utf-8") as f:
        samples_by_id = {}
        for system_name, fr_key in key_map.items():
            for r in final_results[fr_key]["results"]:
                sid = r.get("sample_id")
                if sid not in samples_by_id:
                    samples_by_id[sid] = {
                        "sample_id": sid,
                        "file_path": r.get("file_path"),
                        "ground_truth_label": r.get("ground_truth_label"),
                        "cwe": r.get("cwe"),
                        "category": r.get("category"),
                        "language": r.get("language"),
                        "systems": {}
                    }
                samples_by_id[sid]["systems"][system_name] = r
        for record in samples_by_id.values():
            f.write(json.dumps(record, default=str) + "\n")
    saved_files["raw_results"] = combined_raw_path

    # Save category metrics
    cat_path = output_dir / "category_metrics.json"
    with open(cat_path, "w", encoding="utf-8") as f:
        json.dump(category_metrics, f, indent=2)
    saved_files["category_metrics"] = cat_path

    # Save language metrics
    lang_path = output_dir / "language_metrics.json"
    with open(lang_path, "w", encoding="utf-8") as f:
        json.dump(language_metrics, f, indent=2)
    saved_files["language_metrics"] = lang_path

    # Save confusion matrices
    cm_path = output_dir / "confusion_matrices.json"
    with open(cm_path, "w", encoding="utf-8") as f:
        json.dump(
            {sys: final_results[key]["confusion_matrix"] for sys, key in key_map.items()},
            f, indent=2,
        )
    saved_files["confusion_matrices"] = cm_path

    # Save comparison table
    comparison = {
        sys: {
            "metrics":          final_results[key]["metrics"],
            "confusion_matrix": final_results[key]["confusion_matrix"],
            "execution_counts": final_results[key].get("execution_counts", {}),
            "latency":          latencies.get(sys, {}),
        }
        for sys, key in key_map.items()
    }
    if confidence_stats:
        comparison["full_ace"]["confidence_statistics"] = confidence_stats

    comp_path = output_dir / "comparison.json"
    with open(comp_path, "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)
    saved_files["comparison"] = comp_path

    # Save experiment config
    cfg_path = output_dir / "experiment_config.json"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump({
            "experiment_name":    final_results["experiment_name"],
            "experiment_version": final_results["experiment_version"],
            "timestamp":          final_results["timestamp"],
            "dataset":            final_results["dataset"],
            "sandbox_oracle":     {
                "status": SANDBOX_ORACLE_STATUS,
                "reason": SANDBOX_ORACLE_REASON,
            },
            "status_model": [
                ExecutionStatus.COMPLETED,
                ExecutionStatus.FAILED,
                ExecutionStatus.NOT_RUN,
                ExecutionStatus.NOT_APPLICABLE,
                ExecutionStatus.TIMEOUT,
            ],
            "llm_configuration": {
                "provider": "groq",
                "model": os.getenv("DEFAULT_LLM_MODEL", "qwen/qwen3.8-27b"),
                "base_url": os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1"),
            },
        }, f, indent=2)
    saved_files["config"] = cfg_path

    # Save README
    readme_path = output_dir / "README.md"
    readme_content = f"""# Dataset B Full ACE Benchmark Results (Phase 3.4)

- **Experiment Name:** {final_results["experiment_name"]}
- **Version:** {final_results["experiment_version"]}
- **Timestamp:** {final_results["timestamp"]}
- **Total Records:** {final_results["dataset"]["total_records"]} (Positive: {final_results["dataset"]["positive_samples"]}, Negative: {final_results["dataset"]["negative_samples"]})
- **Manifest Hash:** `{final_results["dataset"]["manifest_hash"]}`

## Executive Summary

| System | Precision | Recall | F1 | Accuracy | FPR | FNR | Coverage | TP | FP | TN | FN | Mean Latency (ms) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for sys_name, fr_key in key_map.items():
        m = final_results[fr_key]["metrics"]
        cm = final_results[fr_key]["confusion_matrix"]
        lat = latencies.get(sys_name, {}).get("mean_ms", 0.0)
        readme_content += (
            f"| **{sys_name}** | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | "
            f"{m['accuracy']:.4f} | {m['fpr']:.4f} | {m['fnr']:.4f} | {m.get('coverage', 1.0):.4f} | "
            f"{cm['tp']} | {cm['fp']} | {cm['tn']} | {cm['fn']} | {lat:.1f} |\n"
        )

    readme_content += """
## Reproduction Command

```bash
python evaluation/dataset_b/evaluator.py
```
"""
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(readme_content)
    saved_files["readme"] = readme_path

    # If saving to phase3_full_ace, also copy to base dataset_b results directory
    base_dir = _REPO_ROOT / "evaluation" / "results" / "dataset_b"
    if output_dir != base_dir and not str(output_dir).endswith("dry_run"):
        try:
            for item in output_dir.iterdir():
                target_item = base_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, target_item, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, target_item)
        except Exception:
            pass

    return saved_files


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Dataset B Evaluation Runner (Phase 3.4)")
    parser.add_argument("--dry-run", action="store_true", help="Run balanced dry run")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of samples")
    parser.add_argument("--output-dir", type=str, default=None, help="Custom output directory")
    args = parser.parse_args()

    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    if str(_AI_ENGINE) not in sys.path:
        sys.path.insert(0, str(_AI_ENGINE))

    out_dir = Path(args.output_dir) if args.output_dir else None
    if args.dry_run and out_dir is None:
        out_dir = _REPO_ROOT / "evaluation" / "results" / "dataset_b" / "dry_run"
    elif out_dir is None:
        out_dir = _REPO_ROOT / "evaluation" / "results" / "dataset_b" / "phase3_full_ace"

    final_results = run_all_four_experiments(
        sample_limit=args.limit,
        is_dry_run=args.dry_run
    )
    saved_files = save_results(final_results, output_dir=out_dir)

    print("=" * 70)
    print("Phase 3 Full Benchmark Complete")
    print("=" * 70)
    print()
    print("Per-system summary:")
    key_map = {
        "semgrep":       "semgrep_baseline",
        "llm_zero_shot": "llm_zero_shot_baseline",
        "sandbox":       "sandbox_baseline",
        "full_ace":      "full_ace",
    }
    for sys_name, fr_key in key_map.items():
        m    = final_results[fr_key]["metrics"]
        cm   = final_results[fr_key]["confusion_matrix"]
        exec_c = final_results[fr_key].get("execution_counts", {})
        print(
            f"  {sys_name:15s}: P={m['precision']:.4f} R={m['recall']:.4f} "
            f"F1={m['f1']:.4f} Acc={m['accuracy']:.4f}  "
            f"TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}  "
            f"completed={exec_c.get('completed',0)} failed={exec_c.get('failed',0)}"
        )

    print()
    print("Saved files:")
    for name, path in saved_files.items():
        print(f"  {name}: {path}")

    return final_results


if __name__ == "__main__":
    results = main()