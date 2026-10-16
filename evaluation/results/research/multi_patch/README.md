# Multi-Patch Competitive Generation & Selection

## IMPORTANT: Synthetic Test Fixture

This page presents controlled-profile synthetic test results used for **implementation verification only**. These results are **not** real validation evidence, sandbox evidence, compilation evidence, empirical results, or benchmark results.

**Classification**: `SYNTHETIC_TEST_FIXTURE`

These controlled profiles use deterministic seed=42 profiles to verify implementation mechanics in sandbox-less environments. They must never be presented as:
- real validation
- real sandbox evidence
- real compilation evidence
- empirical result
- benchmark result

## Strategy Comparison Table

| Metric | Baseline 1 (First Patch) | Baseline 2 (Best-of-N ACE) | Proposed (AECE Selection) |
|---|---|---|---|
| Avg Confidence | 30.00% | 92.75% | 92.75% |
| Avg Legacy ACE Score | 45.00% | 92.75% | 92.75% |
| Avg Evidence Completeness | 0.667 | 1.000 | 1.000 |
| Compilation Success Rate | 100.00% | 100.00% | 100.00% |
| Validation Success Rate | 0.00% | 100.00% | 100.00% |

## Research Integrity

- Controlled profiles are synthetic fixtures for implementation testing only
- Results do not generalize to real-world performance
- Do not cite as empirical evidence or benchmark performance
- Real production results require real agent execution (PatchGenerationAgent, ValidationAgent, SecurityAgent, ACE/AECE)