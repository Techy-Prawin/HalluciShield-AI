# 17 - Patch Generation

## Overview

The Patch Agent generates fix proposals for detected vulnerabilities and hallucinations using LLM-powered code synthesis.

## Patch Generation Flow

```
Finding (vulnerability/hallucination)
    │
    ▼
┌─────────────────┐
│  Context Gather  │  Read surrounding code, imports, types
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  LLM Generation  │  Groq API with structured prompt
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Diff Format     │  Generate unified diff
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Explanation     │  Human-readable fix description
└────────┬────────┘
         │
         ▼
    Patch Object
```

## Patch Object

```json
{
  "id": "uuid",
  "vulnerability_id": "uuid",
  "hallucination_finding_id": "uuid",
  "diff": "--- a/src/main.py\n+++ b/src/main.py\n@@ -10,3 +10,3 @@\n-    result = input.query('SELECT * FROM users WHERE id=' + user_id)\n+    result = input.query('SELECT * FROM users WHERE id=%s', (user_id,))",
  "explanation": "Fixed SQL injection by using parameterized query instead of string concatenation",
  "status": "PENDING_REVIEW",
  "patch_metadata": {
    "language": "python",
    "target_file": "src/main.py",
    "confidence": 0.87
  }
}
```

## API Endpoints

### Generate Patches

```
POST /api/v1/vulnerabilities/{id}/generate-patches
```

Generates multiple patch candidates for a vulnerability.

### Validate Patch

```
POST /api/v1/vulnerabilities/{id}/validate-patch
```

Validates a single patch in the Docker sandbox.

### Validate Candidates

```
POST /api/v1/vulnerabilities/{id}/validate-candidates
```

Validates multiple patch candidates in parallel.

### Rank Patches

```
POST /api/v1/vulnerabilities/{id}/rank-patches
```

Ranks patch candidates by ACE confidence score.

## LLM Prompt Strategy

The Patch Agent uses structured prompts:

1. **Context injection**: Include surrounding code, imports, type definitions
2. **Task specification**: Clear instruction to fix the specific issue
3. **Output format**: Request unified diff format
4. **Constraints**: Language-specific best practices

## Patch Validation

Before presenting to developer:

1. **Syntax check**: Valid language syntax
2. **Sandbox execution**: Apply patch in isolated Docker container
3. **Test execution**: Run existing test suite
4. **Security scan**: Re-scan for new vulnerabilities
5. **Confidence scoring**: ACE score calculation

## Developer Review

Patches are presented to developers with:
- Diff view (unified format)
- Human-readable explanation
- ACE confidence score
- Validation results
- Approve/Reject buttons

## File Structure

```
ai-engine/app/agents/
├── patch_agent.py           # Patch generation
├── patch_ranker.py          # Ranking by confidence
└── validation_agent.py      # Sandbox validation
```
