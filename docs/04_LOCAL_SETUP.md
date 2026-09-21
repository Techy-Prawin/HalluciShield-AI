# 04 - Local Setup

## Prerequisites

- **Node.js** 20 LTS
- **Python** 3.13
- **Docker** + Docker Compose v2
- **PostgreSQL** (or use Docker)

## Quick Start (Docker Compose)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your credentials (see 05_ENVIRONMENT_VARIABLES.md)

# 2. Start all services
docker-compose up --build

# If host ports 4000 or 3000 are already occupied (PowerShell):
$env:BACKEND_PORT="4001"
$env:FRONTEND_PORT="3001"
$env:NEXT_PUBLIC_API_URL="http://localhost:4001"
docker compose up -d --build

# 3. Verify
curl http://localhost:4000/api/v1/health   # Backend
curl http://localhost:8000/api/v1/health   # AI Engine
# Open http://localhost:3000               # Frontend
# Or http://localhost:3001 when using the alternate port above.
```

## Manual Setup

### 1. Environment Configuration

```bash
cp .env.example .env
```

Required variables (see `05_ENVIRONMENT_VARIABLES.md`):
- `DATABASE_URL` - PostgreSQL connection string
- `LLM_BASE_URL` - LLM provider base URL (Groq)
- `LLM_API_KEY` - LLM provider API key

### 2. Backend

```bash
cd backend
npm install
npm run build      # Compile TypeScript
npm run dev        # Start with hot-reload (port 4000)
```

### 3. AI Engine

```bash
cd ai-engine
python -m venv .venv
source .venv/bin/activate   # Linux/Mac
# .\.venv\Scripts\Activate.ps1    # Windows PowerShell

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app --reload-exclude=.venv
```

`--reload-dir app` prevents Windows Uvicorn reloads when files inside the
virtual environment change during dependency installation.

If you invoke Python directly instead of activating the environment, use
`\.\ai-engine\.venv\Scripts\python.exe` from the repository root, or
`\.venv\Scripts\python.exe` from inside `ai-engine`.

### 4. Frontend

```bash
cd frontend
npm install
npm run dev        # Start dev server (port 3000)
```

### 5. Database

Ensure PostgreSQL is running and the schema is applied:

```bash
cd backend
# Schema is at src/db/schema.sql
# Migration runner:
npm run migrate
```

## Running Tests

```bash
# Backend (Jest)
cd backend && npm test

# AI Engine (pytest)
cd ai-engine && python -m pytest tests/ -v

# Frontend (Vitest)
cd frontend && npm test
```

## Service Health Checks

```bash
# Backend
curl http://localhost:4000/api/v1/health

# AI Engine
curl http://localhost:8000/api/v1/health

# Frontend (browser)
open http://localhost:3000
```

## Database Verification

```bash
psql $DATABASE_URL -c "SELECT COUNT(*) FROM users;"
psql $DATABASE_URL -c "SELECT COUNT(*) FROM repositories;"
```
