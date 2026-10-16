# Hallucination-to-Vulnerability Causal Analysis

## IMPORTANT: Controlled Pilot Evidence

This page presents causal analysis results from controlled-profile synthetic test fixtures used for **implementation verification only**. These results are **not** real validation evidence, empirical results, or benchmark results.

**Classification**: `CONTROLLED_PILOT`

The existing 4-case causal experiment uses deterministic controlled profiles and must NOT be presented as:
- real validation evidence
- empirical result
- benchmark result
- generalizable performance finding

### Causal Metrics Table (Synthetic Pilot)

| Metric | Value |
|---|---|
| Total Vulnerabilities Analyzed | 4 |
| Total Hallucinations Detected | 3 |
| Causal Supported Cases | 3 |
| Causal Plausible Cases | 0 |
| No Causal Evidence Cases | 1 |
| Hallucination-to-Vulnerability Rate | 75.00% |
| Causal Attribution Precision | 100.00% |
| Causal Attribution Coverage | 100.00% |

### Research Integrity

- Controlled profiles are synthetic fixtures for implementation testing only
- Results do not generalize to real-world performance
- Do not cite as empirical evidence or benchmark performance
- Real production causal attribution requires actual evidence from HallucinationDetectionAgent, DependencyAnalysisAgent, SecurityAnalysisAgent
- Causal classification must be based on actual evidence, not forced attribution
- If causality cannot be established: `UNKNOWN`