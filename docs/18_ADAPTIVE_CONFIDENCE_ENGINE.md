# 18 - Adaptive Confidence Engine

## Overview

The Adaptive Confidence Engine (ACE) calculates a deterministic, explainable confidence score for every proposed patch. Scores range from 0.0 (low confidence) to 1.0 (high confidence).

## Scoring Formula

```
C = w_h * S_h + w_s * S_s + w_d * S_d + w_p * S_p
```

| Component | Symbol | Description |
|-----------|--------|-------------|
| Hallucination Score | S_h | Severity of detected hallucinations |
| Security Score | S_s | Severity of security vulnerabilities |
| Dependency Score | S_d | Dependency validation results |
| Patch Score | S_p | Sandbox validation pass rate |

## Weight Calibration

### Initial Weights

```json
{
  "w_h": 0.30,
  "w_s": 0.35,
  "w_d": 0.15,
  "w_p": 0.20
}
```

### Bayesian Updating

Weights are calibrated over time using developer feedback:

1. Developer approves/rejects a patch
2. Feedback recorded with reasons
3. Bayesian online updating adjusts weights
4. Updated weights stored in `adaptive_weights` table

### Weight Storage

```sql
CREATE TABLE adaptive_weights (
    id UUID PRIMARY KEY,
    version INT UNIQUE,
    weights_json JSONB,
    is_active BOOLEAN,
    updated_at TIMESTAMPTZ
);
```

## Score Components

### Hallucination Score (S_h)

Based on:
- Number of hallucinations found
- Severity of each hallucination
- Type (phantom method vs. invalid import)

### Security Score (S_s)

Based on:
- Number of vulnerabilities found
- CWE severity ratings
- Exploitability factors

### Dependency Score (S_d)

Based on:
- Phantom package count
- Version mismatch count
- Known vulnerability count

### Patch Score (S_p)

Based on:
- Sandbox validation results
- Unit test pass rate
- Security scan results post-patch

## API Endpoints

### Get Current Weights

```
GET /api/v1/learning/weights
```

Returns active weight profile.

### Submit Feedback

```
POST /api/v1/learning/feedback
```

Developer approval/rejection triggers weight update.

### Get Score Explanation

```
GET /api/v1/vulnerabilities/{id}/patches/{pid}/explanation
```

Returns detailed score breakdown and explanation.

## Score Explanation Example

```json
{
  "final_score": 0.87,
  "breakdown": {
    "hallucination": { "score": 0.92, "weight": 0.30, "contribution": 0.276 },
    "security": { "score": 0.85, "weight": 0.35, "contribution": 0.298 },
    "dependency": { "score": 0.95, "weight": 0.15, "contribution": 0.143 },
    "patch": { "score": 0.80, "weight": 0.20, "contribution": 0.160 }
  },
  "explanation": "High confidence: patch passes all validation checks with minimal risk indicators"
}
```

## File Structure

```
ai-engine/app/agents/
├── confidence_engine.py     # ACE scoring logic
├── adaptive_learning.py     # Weight calibration
└── models.py                # Score models
```
