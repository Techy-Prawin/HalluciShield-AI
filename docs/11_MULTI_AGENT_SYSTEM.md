# 11 - Multi-Agent System

## Overview

HalluciShield uses a multi-agent architecture where specialized agents handle different aspects of code analysis. Agents communicate via internal function calls (not HTTP) within the AI engine process.

## Agent Architecture

```
                    ┌──────────────────┐
                    │  Risk Engine     │
                    │  (Aggregator)    │
                    └───┬──────┬───┬──┘
                        │      │   │
          ┌─────────────▼┐ ┌───▼───▼──────────────┐
          │ Hallucination │ │ Security   │ Dependency│
          │ Agent         │ │ Agent      │ Agent     │
          └───────┬───────┘ └─────┬─────┘ └────┬────┘
                  │               │             │
          ┌───────▼───────┐ ┌─────▼─────┐ ┌────▼────┐
          │ LLM Client    │ │ Semgrep   │ │ Registry│
          │ (Groq API)    │ │ Scanner   │ │ Lookup  │
          └───────────────┘ └───────────┘ └─────────┘
```

## Agents

### Hallucination Detection Agent

**File**: `ai-engine/app/agents/hallucination_agent.py`

Detects LLM-generated code hallucinations:
- **Phantom Methods**: Methods that don't exist in referenced libraries
- **Invalid Imports**: Importing non-existent packages or modules
- **Signature Mismatch**: Function calls with wrong argument types/counts
- **Context Drift**: Code that references variables/functions from wrong scope

Uses LLM (Groq API) with structured prompts and AST analysis.

### Security Analysis Agent

**File**: `ai-engine/app/agents/security_agent.py`

Static security analysis using Semgrep:
- SQL Injection (CWE-89)
- Cross-Site Scripting (CWE-79)
- Hardcoded Secrets (CWE-798)
- Command Injection (CWE-78)
- Path Traversal (CWE-22)
- Insecure JWT Usage (CWE-347)

### Dependency Analysis Agent

**File**: `ai-engine/app/agents/dependency_agent.py`

Validates dependencies against public registries:
- PyPI package existence verification
- npm package existence verification
- Version compatibility checking
- Known vulnerability detection

### Risk Engine

**File**: `ai-engine/app/agents/risk_engine.py`

Aggregates findings from all agents into a unified risk assessment:
- Combines hallucination, security, and dependency scores
- Calculates overall risk level (LOW/MEDIUM/HIGH/CRITICAL)
- Provides breakdown by category

### Patch Agent

**File**: `ai-engine/app/agents/patch_agent.py`

Generates fix proposals using LLM:
- Takes vulnerability/hallucination finding as input
- Generates diff-style patches
- Produces human-readable explanations

### Validation Agent

**File**: `ai-engine/app/agents/validation_agent.py`

Validates patches in isolated Docker sandbox:
- Applies patch to target file
- Runs compilation check
- Executes unit tests
- Runs security scanner
- Returns structured validation results

### Confidence Engine (ACE)

**File**: `ai-engine/app/agents/confidence_engine.py`

Calculates explainable confidence scores:
- Weighted combination of analysis components
- Bayesian weight calibration from feedback
- Score breakdown and explanation generation

### Patch Ranker

**File**: `ai-engine/app/agents/patch_ranker.py`

Ranks multiple patch candidates by ACE confidence score.

### Adaptive Learning

**File**: `ai-engine/app/agents/adaptive_learning.py`

Processes developer feedback to calibrate ACE weights over time.

## Communication Pattern

1. Backend calls AI engine endpoint (e.g., `POST /api/v1/risk/assess`)
2. Risk engine instantiates and calls individual agents
3. Each agent performs analysis independently
4. Risk engine aggregates results
5. Response returned to backend

## LLM Integration

**File**: `ai-engine/app/agents/llm_client.py`

- Uses Groq API (OpenAI-compatible endpoint)
- Model: `openai/gpt-oss-20b`
- Structured JSON responses via `chat_json()`
- Prompt injection protection via `sanitize_for_llm_prompt()`
- Rate limiting built into middleware
