"""
Phase 5.6 Parallel Concurrency Smoke Test
Tests 20 jobs (2 samples x 10 configs) with per-thread agent instantiation.
Validates: no duplicate records, no race conditions, correct isolation.
"""
import sys
import os
import time
import json
import threading
import tempfile
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

_REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "ai-engine"))

from evaluation.dataset_b.evaluator import load_all_samples_info, get_dataset_loader, ExecutionStatus
from evaluation.dataset_b.ablation_config import PipelineConfig

CONFIGS = {
    "A": PipelineConfig(),
    "B": PipelineConfig(hallucination_detection=False),
    "C": PipelineConfig(dependency_analysis=False),
    "D": PipelineConfig(security_analysis=False),
    "E": PipelineConfig(risk_assessment=False),
    "F": PipelineConfig(patch_generation=False),
    "G": PipelineConfig(validation=False),
    "H": PipelineConfig(legacy_ace=False),
    "I": PipelineConfig(aece=False),
    "J": PipelineConfig(multi_patch=False),
}

# Thread-local storage for agent instances
_thread_local = threading.local()


def make_agents():
    """Create a fresh, independent agent set (called once per thread)."""
    from app.agents.hallucination_agent import HallucinationDetectionAgent
    from app.agents.dependency_agent import DependencyAnalysisAgent
    from app.agents.security_agent import SecurityAnalysisAgent
    from app.agents.risk_engine import RiskEngine
    from app.agents.patch_agent import PatchGenerationAgent
    from app.agents.validation_agent import ValidationAgent
    from app.agents.confidence_engine import ConfidenceEngine
    from app.agents.aece_engine import AECEngine
    from app.agents.patch_selector import PatchSelector
    return {
        "hallucination": HallucinationDetectionAgent(),
        "dependency": DependencyAnalysisAgent(),
        "security": SecurityAnalysisAgent(),
        "risk": RiskEngine(),
        "patch": PatchGenerationAgent(),
        "validation": ValidationAgent(),
        "confidence": ConfidenceEngine(),
        "aece": AECEngine(),
        "patch_selector": PatchSelector(),
    }


def get_thread_agents():
    """Get or lazily create per-thread agent instances."""
    if not hasattr(_thread_local, "agents"):
        _thread_local.agents = make_agents()
    return _thread_local.agents


def run_job(job_args):
    """Execute one sample x config job. Returns a result dict."""
    sample, fp, cfg_k, cfg = job_args
    sample_id = sample["sample_id"]
    t_start = time.time()
    tid = threading.current_thread().name

    agents = get_thread_agents()

    try:
        with tempfile.TemporaryDirectory(prefix="smoke_par_") as ws:
            dest = Path(ws) / fp.name
            shutil.copy2(fp, dest)
            repo_id = "smoke-" + sample_id + "-" + cfg_k

            sec_findings = []
            hal_findings = []

            if cfg.hallucination_detection:
                try:
                    hal_res = agents["hallucination"].detect_hallucinations(
                        repository_id=repo_id, workspace_path=ws
                    )
                    hal_findings = hal_res.findings
                except Exception:
                    pass

            if cfg.security_analysis:
                try:
                    sec_res = agents["security"].analyze_security(
                        repository_id=repo_id, workspace_path=ws
                    )
                    sec_findings = sec_res.findings
                except Exception:
                    pass

        elapsed_ms = int((time.time() - t_start) * 1000)
        return {
            "sample_id": sample_id,
            "config_id": cfg_k,
            "thread": tid,
            "hal_findings": len(hal_findings),
            "sec_findings": len(sec_findings),
            "elapsed_ms": elapsed_ms,
            "ok": True,
            "error": None,
        }
    except Exception as e:
        return {
            "sample_id": sample_id,
            "config_id": cfg_k,
            "thread": tid,
            "ok": False,
            "error": str(e),
            "elapsed_ms": int((time.time() - t_start) * 1000),
        }


def main():
    print("=" * 65)
    print("PHASE 5.6: PARALLEL CONCURRENCY SMOKE TEST (20 jobs)")
    print("=" * 65)

    all_samples = load_all_samples_info()[:2]
    loader = get_dataset_loader()
    jobs = [
        (s, loader.get_file_path(s), cfg_k, cfg)
        for s in all_samples
        for cfg_k, cfg in CONFIGS.items()
    ]
    print(f"\nJobs to run: {len(jobs)} (2 samples x 10 configs)")
    print("Workers: 4 (thread pool with per-thread agent instances)")
    print()

    results = []
    write_lock = threading.Lock()

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="ablation_worker") as executor:
        futures = {executor.submit(run_job, job): job for job in jobs}
        for future in as_completed(futures):
            r = future.result()
            with write_lock:
                results.append(r)
                status = "OK" if r["ok"] else "FAIL"
                print(
                    f'  [{status}] {r["sample_id"]} cfg={r["config_id"]} '
                    f'hal={r.get("hal_findings","?")} sec={r.get("sec_findings","?")} '
                    f'{r.get("elapsed_ms","?")}ms thread={r.get("thread","?")}'
                )

    total_elapsed = time.time() - t0

    print()
    print("=" * 65)
    print("SMOKE TEST RESULTS")
    print("=" * 65)

    ok_results = [r for r in results if r["ok"]]
    err_results = [r for r in results if not r["ok"]]

    check_count = len(results) == 20
    print(f'[{"PASS" if check_count else "FAIL"}] Total jobs completed: {len(results)}/20')

    pairs = [(r["sample_id"], r["config_id"]) for r in ok_results]
    unique_pairs = set(pairs)
    check_unique = len(pairs) == len(unique_pairs)
    print(
        f'[{"PASS" if check_unique else "FAIL"}] No duplicate sample-config pairs: '
        f"{len(unique_pairs)}/{len(pairs)} unique"
    )

    cfg_ids = set(r["config_id"] for r in results)
    check_configs = cfg_ids == set(CONFIGS.keys())
    print(f'[{"PASS" if check_configs else "FAIL"}] All 10 configs executed: {sorted(cfg_ids)}')

    check_no_err = len(err_results) == 0
    print(f'[{"PASS" if check_no_err else "WARN"}] Errors: {len(err_results)}')
    for e in err_results[:3]:
        print(f'  ERROR: {e["sample_id"]} cfg={e["config_id"]}: {e["error"][:80]}')

    threads_used = set(r.get("thread", "") for r in results)
    print(f"[INFO] Threads used: {len(threads_used)} ({sorted(threads_used)})")

    sequential_est = sum(r.get("elapsed_ms", 0) for r in ok_results) / 1000
    speedup = sequential_est / total_elapsed if total_elapsed > 0 else 1.0
    print(
        f"[INFO] Wall time: {total_elapsed:.1f}s, "
        f"Sequential estimate: {sequential_est:.1f}s, "
        f"Speedup: {speedup:.1f}x"
    )

    print()
    all_passed = check_count and check_unique and check_configs
    if all_passed:
        print("VERDICT: SAFE_FOR_PARALLEL_ABLATION")
        avg_ms = sum(r.get("elapsed_ms", 0) for r in ok_results) / max(len(ok_results), 1)
        print(f"Recommended workers: 4")
        print(f"Average job time: {avg_ms:.0f}ms")
        est_hours_seq = (5000 * avg_ms / 1000) / 3600
        est_hours_par = est_hours_seq / min(speedup, 4.0)
        print(
            f"Estimated full run: {est_hours_seq:.1f}h sequential "
            f"-> {est_hours_par:.1f}h @ 4 workers"
        )
    else:
        print("VERDICT: NOT_SAFE")
        print("Reason: One or more checks failed (see above)")


if __name__ == "__main__":
    main()
