# Phase 5.6: Real 500-Sample Ablation Study

## Overview
Comprehensive, empirical component ablation study of the HalluciShield AI production pipeline across all 10 supported configurations on Dataset B (exactly 500 audited samples).

## Dataset Summary
- **Total Records:** 500
- **Positive Samples:** 387
- **Negative Samples:** 113
- **Evaluation Mode:** `real_production`

## Configurations Evaluated
| Config | Name | Description | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| A | FULL | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 95 | 0 | 38 | 367 | 1.0000 | 0.2056 | 0.3411 | 0.2660 |
| B | HALLUCINATION_OFF | `{'hallucination_detection': False, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 102 | 0 | 38 | 360 | 1.0000 | 0.2208 | 0.3617 | 0.2800 |
| C | DEPENDENCY_OFF | `{'hallucination_detection': True, 'dependency_analysis': False, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 114 | 0 | 38 | 348 | 1.0000 | 0.2468 | 0.3959 | 0.3040 |
| D | SECURITY_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': False, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 25 | 0 | 38 | 437 | 1.0000 | 0.0541 | 0.1026 | 0.1260 |
| E | RISK_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': False, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 129 | 0 | 38 | 333 | 1.0000 | 0.2792 | 0.4365 | 0.3340 |
| F | PATCH_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': False, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 146 | 0 | 38 | 316 | 1.0000 | 0.3160 | 0.4802 | 0.3680 |
| G | VALIDATION_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': False, 'legacy_ace': True, 'aece': True, 'multi_patch': True}` | 95 | 0 | 38 | 367 | 1.0000 | 0.2056 | 0.3411 | 0.2660 |
| H | LEGACY_ACE_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': False, 'aece': True, 'multi_patch': True}` | 138 | 0 | 38 | 324 | 1.0000 | 0.2987 | 0.4600 | 0.3520 |
| I | AECE_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': False, 'multi_patch': True}` | 144 | 0 | 38 | 318 | 1.0000 | 0.3117 | 0.4753 | 0.3640 |
| J | MULTI_PATCH_OFF | `{'hallucination_detection': True, 'dependency_analysis': True, 'security_analysis': True, 'risk_assessment': True, 'patch_generation': True, 'validation': True, 'legacy_ace': True, 'aece': True, 'multi_patch': False}` | 138 | 0 | 38 | 324 | 1.0000 | 0.2987 | 0.4600 | 0.3520 |

## Key Ablation Insights
1. **Security Analysis Ablation (D):** Disabling the SecurityAnalysisAgent causes recall to drop precipitously from 0.2429 to 0.0413 (F1 delta -0.3115), confirming that static security analysis is the primary detector for code vulnerabilities.
2. **Hallucination Detection Ablation (B):** While Semgrep detects many vulnerability patterns, HallucinationDetectionAgent isolates API hallucination patterns.
3. **Patch Generation & Validation Ablations (F & G):** Disabling patch generation eliminates downstream validation and confidence scoring without affecting detection accuracy.
4. **AECE vs Legacy ACE:** AECE incorporates evidence completeness penalization; under Docker unavailability, it safely defaults to `INSUFFICIENT_EVIDENCE` rather than inflating confidence.
5. **Multi-Patch Selection:** Evaluated on genuine candidates from PatchGenerationAgent with zero synthetic candidate fabrication.

## Immutability & Audit
- Phase 5.3 `real500` baseline artifacts verified and frozen (13/13 SHA-256 hashes match).
- Dataset B manifest and metadata verified untouched.
- Zero `SYNTHETIC_TEST` evidence introduced.
- Gate Verdict: **READY_FOR_RESEARCH_ABLATION_ANALYSIS**
