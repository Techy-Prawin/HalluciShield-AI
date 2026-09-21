# HalluciShield AI

> **An Adaptive Multi-Agent Confidence Framework for Detecting and Mitigating Hallucination-Induced Software Vulnerabilities in AI-Generated Code**

---

## Workspace Directory Overview

```
HalluciShield_antigravity/
├── frontend/             # Next.js, TypeScript, Pure CSS Dashboard Portal
├── backend/              # Node.js, Express, TypeScript API Gateway & Orchestrator
├── ai-engine/            # Python, FastAPI Service & Adaptive Confidence Engine (ACE)
├── sandbox/              # Isolated Docker Execution Runtime Specifications
├── docs/                 # System Architecture, API Specs & DB Schemas
├── tests/                # System Integration Health Test Suites
├── docker-compose.yml    # Multi-service local environment setup
├── .env.example          # Baseline environment template
└── README.md             # Project documentation
```

---

## Quickstart Guide

### 1. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 2. Local Service Execution via Docker Compose
Start PostgreSQL, Backend, AI Engine, and Frontend:
```bash
docker-compose up --build
```

### 3. Individual Local Development Setup

#### Express Backend:
```bash
cd backend
npm install
npm run dev
```

#### Python FastAPI AI Engine:
```bash
cd ai-engine
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python app/main.py
```

#### Next.js Frontend:
```bash
cd frontend
npm install
npm run dev
```

---

## Verifying Service Health Endpoints

- **Backend Health:** `GET http://localhost:4000/api/v1/health`
- **AI Engine Health:** `GET http://localhost:8000/api/v1/health`
- **Frontend Dashboard:** `http://localhost:3000`

---

## Running Test Suites

Run unit and integration tests across all modules:
```bash
# Backend Jest tests
npm run test:backend

# Frontend Vitest tests
npm run test:frontend

# AI Engine Pytest tests
npm run test:ai
```
