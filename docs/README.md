# HalluciShield Documentation

> **An Adaptive Multi-Agent Confidence Framework for Detecting and Mitigating Hallucination-Induced Software Vulnerabilities in AI-Generated Code**

---

## Documentation Index

| # | Document | Description |
|---|----------|-------------|
| 01 | [Project Overview](01_PROJECT_OVERVIEW.md) | Mission, research goals, and key features |
| 02 | [System Architecture](02_SYSTEM_ARCHITECTURE.md) | High-level service topology and data flow |
| 03 | [Tech Stack](03_TECH_STACK.md) | Languages, frameworks, databases, and tooling |
| 04 | [Local Setup](04_LOCAL_SETUP.md) | Step-by-step development environment setup |
| 05 | [Environment Variables](05_ENVIRONMENT_VARIABLES.md) | All environment variables explained |
| 06 | [Docker Configuration](06_DOCKER_CONFIGURATION.md) | Docker Compose, Dockerfiles, and networking |
| 07 | [Shared Workspace](07_SHARED_WORKSPACE.md) | Docker shared-workspace architecture |
| 08 | [Database](08_DATABASE.md) | PostgreSQL schema, tables, and migrations |
| 09 | [Backend API](09_BACKEND_API.md) | Express backend routes, middleware, and orchestration |
| 10 | [AI Engine API](10_AI_ENGINE_API.md) | FastAPI routes and endpoint reference |
| 11 | [Multi-Agent System](11_MULTI_AGENT_SYSTEM.md) | Agent architecture and communication |
| 12 | [Upload Flow](12_UPLOAD_FLOW.md) | Repository upload and extraction pipeline |
| 13 | [Scan Orchestration](13_SCAN_ORCHESTRATION.md) | Scan lifecycle and status management |
| 14 | [Hallucination Detection](14_HALLUCINATION_DETECTION.md) | Hallucination detection strategies |
| 15 | [Security Analysis](15_SECURITY_ANALYSIS.md) | Vulnerability detection with Semgrep |
| 16 | [Dependency Analysis](16_DEPENDENCY_ANALYSIS.md) | Dependency validation against registries |
| 17 | [Patch Generation](17_PATCH_GENERATION.md) | LLM-powered patch creation |
| 18 | [Adaptive Confidence Engine](18_ADAPTIVE_CONFIDENCE_ENGINE.md) | ACE scoring model and weight calibration |
| 19 | [Validation Sandbox](19_VALIDATION_SANDBOX.md) | Docker sandbox for patch validation |
| 20 | [Frontend](20_FRONTEND.md) | Next.js dashboard and UI components |
| 21 | [Deployment](21_DEPLOYMENT.md) | Production deployment guide |
| 22 | [Testing](22_TESTING.md) | Test suites and coverage |
| 23 | [Troubleshooting](23_TROUBLESHOOTING.md) | Common issues and debugging |
| 24 | [Developer Guide](24_DEVELOPER_GUIDE.md) | Contributing, code style, and conventions |
| - | [Run Locally](RUN_LOCALLY.md) | Quick local setup guide |
| - | [How to Run Project Locally](HOW_TO_RUN_PROJECT_LOCALLY.md) | **Complete beginner guide — start here** |

---

## Architecture Diagram

```
                    ┌─────────────────┐
                    │    Frontend     │
                    │  Next.js :3000  │
                    └────────┬────────┘
                             │ HTTP
                    ┌────────▼────────┐
                    │    Backend      │
                    │  Express :4000  │
                    │  (Orchestrator) │
                    └───┬────────┬────┘
                        │        │
            ┌───────────▼──┐  ┌──▼────────────┐
            │  PostgreSQL  │  │  AI Engine     │
            │  :5432       │  │  FastAPI :8000 │
            └──────────────┘  │  (Agents)      │
                              └───┬────────────┘
                                  │ reads
                    ┌─────────────▼─────────────┐
                    │   Shared Workspace Volume  │
                    │   /workspace/runs/<scanId> │
                    │   /workspace/archives/     │
                    └───────────────────────────┘
```

## Ports

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | Next.js dashboard |
| Backend | 4000 | Express API gateway |
| AI Engine | 8000 | FastAPI analysis service |
| PostgreSQL | 5432 | Database |
