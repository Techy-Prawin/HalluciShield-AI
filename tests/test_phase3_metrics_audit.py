#!/usr/bin/env python3
"""Unit test: verify TP/FP/TN/FN logic and all four metric cases.

Rules:
  - positive label + predicted positive  -> TP
  - negative label + predicted positive  -> FP
  - negative label + predicted negative  -> TN
  - positive label + predicted negative  -> FN
"""
import sys, json, unittest
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "ai-engine"))
sys.path.insert(0, str(ROOT / "evaluation"))

from evaluation.dataset_b.evaluator import compute_confusion_matrix, compute_metrics


class TestMetricsCases(unittest.TestCase):
    """Verify all four TP/FP/TN/FN cases."""

    def _make_record(self, label, predicted_label):
        detected = predicted_label == "positive"
        return {
            "label": label,
            "predicted_label": predicted_label,
            "detection_correct": (detected and label == "positive") or (not detected and label == "negative"),
            "false_positive": detected and label == "negative",
            "false_negative": not detected and label == "positive",
        }

    def test_tp(self):
        r = self._make_record("positive", "positive")
        cm = compute_confusion_matrix([r])
        self.assertEqual(cm, {"tp": 1, "fp": 0, "tn": 0, "fn": 0})

    def test_fp(self):
        r = self._make_record("negative", "positive")
        cm = compute_confusion_matrix([r])
        self.assertEqual(cm, {"tp": 0, "fp": 1, "tn": 0, "fn": 0})

    def test_tn(self):
        r = self._make_record("negative", "negative")
        cm = compute_confusion_matrix([r])
        self.assertEqual(cm, {"tp": 0, "fp": 0, "tn": 1, "fn": 0})

    def test_fn(self):
        r = self._make_record("positive", "negative")
        cm = compute_confusion_matrix([r])
        self.assertEqual(cm, {"tp": 0, "fp": 0, "tn": 0, "fn": 1})

    def test_dataset_b_totals(self):
        """Verify reported dataset split: 387 positive, 113 negative = 500 total."""
        from evaluation.dataset_b.dataset_loader import DatasetBLoader
        loader = DatasetBLoader(
            metadata_csv=ROOT / "dataset/dataset-b/metadata.csv",
            files_root=ROOT / "dataset/dataset/dataset-b",
        )
        samples = loader.get_samples()
        pos = sum(1 for s in samples if s["label"] == "positive")
        neg = sum(1 for s in samples if s["label"] == "negative")
        total = len(samples)
        self.assertEqual(total, 500, f"Expected 500 samples, got {total}")
        self.assertEqual(pos, 387, f"Expected 387 positives, got {pos}")
        self.assertEqual(neg, 113, f"Expected 113 negatives, got {neg}")

    def test_all_predicted_negative_gives_tn113_fn387(self):
        """All-negative prediction on the real dataset must give TN=113, FN=387."""
        from evaluation.dataset_b.dataset_loader import DatasetBLoader
        loader = DatasetBLoader(
            metadata_csv=ROOT / "dataset/dataset-b/metadata.csv",
            files_root=ROOT / "dataset/dataset/dataset-b",
        )
        samples = loader.get_samples()
        records = []
        for s in samples:
            label = s["label"]
            predicted = "negative"
            records.append(self._make_record(label, predicted))
        cm = compute_confusion_matrix(records)
        self.assertEqual(cm["tp"], 0)
        self.assertEqual(cm["fp"], 0)
        self.assertEqual(cm["tn"], 113)
        self.assertEqual(cm["fn"], 387)

    def test_semgrep_raw_results_match_expected_cm(self):
        """Semgrep raw_results.jsonl must produce TP=0,FP=0,TN=113,FN=387."""
        path = ROOT / "evaluation/results/dataset_b/semgrep/raw_results.jsonl"
        records = [json.loads(l) for l in open(path)]
        self.assertEqual(len(records), 500)
        cm = compute_confusion_matrix(records)
        self.assertEqual(cm["tp"], 0)
        self.assertEqual(cm["fp"], 0)
        self.assertEqual(cm["tn"], 113)
        self.assertEqual(cm["fn"], 387)

    def test_llm_raw_results_only_one_record(self):
        """LLM raw_results.jsonl should have 500 records but only has 1 (bug)."""
        path = ROOT / "evaluation/results/dataset_b/llm_zero_shot/raw_results.jsonl"
        records = [json.loads(l) for l in open(path)]
        # Document the bug: should be 500 but is 1
        self.assertEqual(len(records), 1, 
            f"LLM LOOP BUG confirmed: only {len(records)} record instead of 500")

    def test_full_ace_all_error_status(self):
        """Full ACE must show scanner_result='error' for all 500 (module not found)."""
        path = ROOT / "evaluation/results/dataset_b/full_ace/raw_results.jsonl"
        records = [json.loads(l) for l in open(path)]
        error_count = sum(1 for r in records if r.get("scanner_result") == "error")
        self.assertEqual(error_count, 500,
            f"Full ACE: {error_count}/500 have error status (expected 500)")

    def test_sandbox_no_oracle(self):
        """Sandbox: COMPLETED samples with vuln code still predict negative (no oracle)."""
        path = ROOT / "evaluation/results/dataset_b/sandbox/raw_results.jsonl"
        records = [json.loads(l) for l in open(path)]
        # All COMPLETED positive samples should still be predicted negative
        completed_pos = [r for r in records 
                        if r.get("execution_status") == "COMPLETED" and r["label"] == "positive"]
        false_negatives = [r for r in completed_pos if r["predicted_label"] == "negative"]
        self.assertEqual(len(false_negatives), len(completed_pos),
            f"Sandbox: {len(false_negatives)}/{len(completed_pos)} completed positive samples predicted negative")

    def test_metrics_precision_recall_f1(self):
        """Verify precision/recall/F1 formulas with all-negative prediction."""
        m = compute_metrics(tp=0, fp=0, fn=387, tn=113)
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)
        self.assertEqual(m["f1"], 0.0)
        self.assertAlmostEqual(m["accuracy"], 113/500, places=3)
        self.assertEqual(m["fpr"], 0.0)
        self.assertEqual(m["fnr"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
