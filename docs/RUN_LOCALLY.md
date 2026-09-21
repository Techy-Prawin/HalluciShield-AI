# How to Run HalluciShield Locally

A complete guide to running HalluciShield on your local machine.

---

## Prerequisites

Install these before starting:

| Tool | Version | Check Command |
|------|---------|---------------|
| **Node.js** | 20 LTS | `node --version` |
| **npm** | 10+ | `npm --version` |
| **Python** | 3.13 | `python --version` |
| **pip** | Latest | `pip --version` |
| **Docker** | 29+ | `docker --version` |
| **Docker Compose** | v2.40+ | `docker compose version` |
| **Git** | Any | `git --version` |

### Install Docker Desktop

Download from [docker.com](https://www.docker.com/products/docker-desktop/). This is the easiest way to get PostgreSQL running without installing it separately.

---

## Step 1: Clone the Repository

```bash
git clone <repository-url>
cd HalluciShield
```

---

## Step 2: Configure Environment

```bash
cp .env.example .env
```

Open `.env` and fill in these required values:

```env
# Database (use Docker PostgreSQL or Neon cloud)
DATABASE_URL=postgresql://hallucishield:hallucishield@localhost:5432/hallucishield

# LLM Provider (Groq API)
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=gsk_your_groq_api_key_here

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:4000
```

**Get a Groq API key**: Sign up at [console.groq.com](https://console.groq.com) (free tier available).

---

## Step 3: Start with Docker Compose (Recommended)

This is the fastest way to get everything running:

```bash
docker compose up --build
```

This starts 4 services:
| Service | Port | URL |
|---------|------|-----|
| PostgreSQL | 5432 | `postgresql://localhost:5432` |
| Backend (Express) | 4000 | http://localhost:4000 |
| AI Engine (FastAPI) | 8000 | http://localhost:8000 |
| Frontend (Next.js) | 3000 | http://localhost:3000 |

### Verify Services

```bash
# Check all services are running
docker compose ps

# Backend health
curl http://localhost:4000/api/v1/health

# AI Engine health
curl http://localhost:8000/api/v1/health

# Open frontend in browser
start http://localhost:3000
```

### View Logs

```bash
# All services
docker compose logs -f

# Single service
docker compose logs -f backend
docker compose logs -f ai-engine
```

### Stop Services

```bash
# Stop but keep data
docker compose down

# Stop and delete all data (including database)
docker compose down -v
```

---

## Step 3 (Alternative): Run Without Docker

If you prefer running services individually:

### 3A. Start PostgreSQL

**Option A: Docker only for PostgreSQL**
```bash
docker run -d \
  --name hallucishield-db \
  -e POSTGRES_USER=hallucishield \
  -e POSTGRES_PASSWORD=hallucishield \
  -e POSTGRES_DB=hallucishield \
  -p 5432:5432 \
  postgres:15-alpine
```

**Option B: Local PostgreSQL**

Install PostgreSQL from [postgresql.org](https://www.postgresql.org/download/) and create the database:
```sql
CREATE USER hallucishield WITH PASSWORD 'hallucishield';
CREATE DATABASE hallucishield OWNER hallucishield;
```

### 3B. Start Backend

```bash
cd backend
npm install
npm run build
npm run dev
```

Backend runs on http://localhost:4000

### 3C. Start AI Engine

```bash
cd ai-engine

# Create virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate       # Linux/Mac
# .\.venv\Scripts\Activate.ps1  # Windows PowerShell

pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app --reload-exclude=.venv
```

AI Engine runs on http://localhost:8000

### 3D. Start Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on http://localhost:3000

---

## Step 4: Apply Database Schema

If running without Docker Compose, apply the schema manually:

```bash
# Using psql
psql -U hallucishield -d hallucishield -f backend/src/db/schema.sql

# Or using the migration script
cd backend
npm run migrate
```

Verify the schema was applied:
```bash
psql -U hallucishield -d hallucishield -c "\dt"
```

You should see: `users`, `repositories`, `scans`, `vulnerabilities`, `hallucination_findings`, `patches`, `validation_results`, `confidence_scores`, `developer_feedbacks`, `runtime_events`

---

## Step 5: Test the Full Flow

### Upload a Repository

1. Open http://localhost:3000
2. Drag and drop a `.zip` file containing source code
3. Wait for upload to complete
4. Note the Repository ID

### Trigger a Scan

```bash
# Replace <repo-id> with the actual ID from upload
curl -X POST http://localhost:4000/api/orchestration/scan \
  -H "Content-Type: application/json" \
  -d '{"repositoryId": "<repo-id>"}'
```

Response: `202 Accepted` with `scanId`

### Check Scan Status

```bash
# Replace <scan-id> from the scan response
curl http://localhost:4000/api/orchestration/status/<scan-id>
```

### Get Results

```bash
curl http://localhost:4000/api/orchestration/results/<scan-id>
```

---

## Step 6: Run Tests

### Backend Tests

```bash
cd backend
npm test
```

Expected: 58 tests passing

### AI Engine Tests

```bash
cd ai-engine
python -m pytest tests/ -v
```

Expected: 810 tests passing

### Frontend Tests

```bash
cd frontend
npm test
```

---

## Quick Reference Commands

| Action | Command |
|--------|---------|
| Start everything (Docker) | `docker compose up --build` |
| Stop everything | `docker compose down` |
| Restart backend only | `docker compose restart backend` |
| View backend logs | `docker compose logs -f backend` |
| Rebuild after changes | `docker compose up --build` |
| Run backend tests | `cd backend && npm test` |
| Run AI engine tests | `cd ai-engine && python -m pytest tests/ -v` |
| Check backend health | `curl http://localhost:4000/api/v1/health` |
| Check AI engine health | `curl http://localhost:8000/api/v1/health` |
| Open frontend | `start http://localhost:3000` |
| Reset database | `docker compose down -v && docker compose up --build` |

---

## Common Issues

### Port Already in Use

```bash
# Find what's using port 4000
lsof -i :4000         # Linux/Mac
netstat -ano | findstr :4000  # Windows

# Kill the process
kill <PID>
```

### Database Connection Refused

```bash
# Check if PostgreSQL is running
docker compose ps

# Restart database
docker compose restart hallucishield-db

# Test connection
psql -U hallucishield -d hallucishield -c "SELECT 1;"
```

### LLM API Errors

```bash
# Test Groq API key
curl https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer gsk_your_key_here"
```

### AI Engine Module Not Found

```bash
cd ai-engine
pip install -r requirements.txt
```

### Upload Fails with 413 Error

Archive is too large. Maximum size is 50MB. Compress your archive before uploading.

### Zip-Slip Detection

Recreate your archive using the command line (not GUI archivers):
```bash
cd /path/to/source-code
zip -r /tmp/my-repo.zip .
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `LLM_BASE_URL` | Yes | - | `https://api.groq.com/openai/v1` |
| `LLM_API_KEY` | Yes | - | Groq API key |
| `NEXT_PUBLIC_API_URL` | No | `http://localhost:4000` | Backend URL for frontend |
| `WORKSPACE_ROOT` | No | `backend/uploads/extracted` | Shared workspace root |
| `HALLUCISHIELD_WORKSPACE_ROOT` | No | - | AI engine workspace restriction |
| `JWT_SECRET` | No | auto (dev) | Required in production |
| `HALLUCISHIELD_API_KEY` | No | - | Optional API key auth |

---

## Project Directory After Running

```
HalluciShield/
├── backend/
│   └── uploads/
│       └── extracted/          # Default workspace (local mode)
│           ├── archives/       # Staged ZIP files
│           └── runs/           # Extracted repositories
├── frontend/
├── ai-engine/
├── .env                        # Your configuration
└── docker-compose.yml
```

In Docker mode, the workspace is at `/workspace` inside the containers, backed by the `hallucishield_workspace` named volume.
