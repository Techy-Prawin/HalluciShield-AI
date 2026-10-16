"""
Confidence Calibration Module for HalluciShield AI.

Computes:
1. Brier Score
2. Expected Calibration Error (ECE)
3. Maximum Calibration Error (MCE)
4. Reliability Bins

Follows standard empirical calibration metrics (Guo et al., 2017).
Strictly rejects unavailable or non-binary outcomes.
"""

from typing import Any, Dict, List, Optional, Tuple


def compute_confidence_calibration(
    records: List[Dict[str, Any]],
    num_bins: int = 10,
) -> Dict[str, Any]:
    """
    Compute calibration metrics over a list of evaluated samples.

    Each record must have:
      - 'predicted_confidence': float in [0.0, 1.0] (or 0-100%, normalized to [0,1])
      - 'actual_outcome': 1 or 0 (or True/False) representing validated success
      - 'sample_id' (optional, for tracing)

    Records with actual_outcome = None or NOT_AVAILABLE are strictly excluded.

    Returns:
      {
        "total_evaluated": int,
        "excluded_count": int,
        "brier_score": float,
        "expected_calibration_error": float,
        "max_calibration_error": float,
        "reliability_bins": List[Dict[str, Any]],
      }
    """
    valid_samples: List[Tuple[float, float, str]] = []
    excluded_count = 0

    for idx, r in enumerate(records):
        conf = r.get("predicted_confidence")
        outcome = r.get("actual_outcome")
        sid = str(r.get("sample_id") or r.get("patch_id") or f"sample_{idx}")

        # Strictly filter out unavailable/missing outcomes or confidences
        if conf is None or outcome is None:
            excluded_count += 1
            continue

        if isinstance(outcome, str) and outcome in ("NOT_AVAILABLE", "UNKNOWN", "UNVERIFIED"):
            excluded_count += 1
            continue

        try:
            conf_val = float(conf)
            # Normalize 0-100 scale to 0-1 if necessary
            if conf_val > 1.0:
                conf_val = conf_val / 100.0
            conf_val = max(0.0, min(1.0, conf_val))

            if isinstance(outcome, bool):
                out_val = 1.0 if outcome else 0.0
            elif isinstance(outcome, (int, float)):
                out_val = 1.0 if outcome >= 0.5 else 0.0
            elif isinstance(outcome, str) and outcome.lower() in ("true", "pass", "success", "1"):
                out_val = 1.0
            else:
                out_val = 0.0

            valid_samples.append((conf_val, out_val, sid))
        except (ValueError, TypeError):
            excluded_count += 1
            continue

    n = len(valid_samples)
    if n == 0:
        return {
            "total_evaluated": 0,
            "excluded_count": excluded_count,
            "brier_score": 0.0,
            "expected_calibration_error": 0.0,
            "max_calibration_error": 0.0,
            "reliability_bins": [],
            "status": "NO_VALID_DATA",
        }

    # 1. Brier Score: (1/N) * sum((p - y)^2)
    brier_score = sum((p - y) ** 2 for p, y, _ in valid_samples) / n

    # 2. Binning into M bins
    bin_width = 1.0 / num_bins
    bins: List[List[Tuple[float, float, str]]] = [[] for _ in range(num_bins)]

    for p, y, sid in valid_samples:
        bin_idx = int(p / bin_width)
        if bin_idx >= num_bins:
            bin_idx = num_bins - 1
        bins[bin_idx].append((p, y, sid))

    # 3. ECE & MCE computation
    reliability_bins = []
    ece = 0.0
    mce = 0.0

    for b_idx in range(num_bins):
        lower = round(b_idx * bin_width, 4)
        upper = round((b_idx + 1) * bin_width, 4)
        b_samples = bins[b_idx]
        count = len(b_samples)

        if count > 0:
            avg_conf = sum(p for p, _, _ in b_samples) / count
            obs_acc = sum(y for _, y, _ in b_samples) / count
            gap = abs(avg_conf - obs_acc)
            ece += (count / n) * gap
            mce = max(mce, gap)
        else:
            avg_conf = (lower + upper) / 2.0
            obs_acc = 0.0
            gap = 0.0

        reliability_bins.append({
            "bin_index": b_idx,
            "range": [lower, upper],
            "sample_count": count,
            "mean_confidence": round(avg_conf, 4),
            "observed_accuracy": round(obs_acc, 4),
            "calibration_gap": round(gap, 4),
        })

    return {
        "total_evaluated": n,
        "excluded_count": excluded_count,
        "brier_score": round(brier_score, 4),
        "expected_calibration_error": round(ece, 4),
        "max_calibration_error": round(mce, 4),
        "reliability_bins": reliability_bins,
        "status": "COMPLETED",
    }


class CalibrationEngine:
    """Class wrapper for confidence calibration metrics."""

    def __init__(self, num_bins: int = 10):
        self.num_bins = num_bins

    def calculate_calibration(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        return compute_confidence_calibration(records, num_bins=self.num_bins)

    def compute_reliability_diagram_data(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        calib = self.calculate_calibration(records)
        return {
            "bins": calib.get("reliability_bins", []),
            "brier_score": calib.get("brier_score", 0.0),
            "ece": calib.get("expected_calibration_error", 0.0),
            "mce": calib.get("max_calibration_error", 0.0),
        }

