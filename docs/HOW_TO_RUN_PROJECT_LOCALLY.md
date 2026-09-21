# How to Run HalluciShield Project Locally

A complete, beginner-friendly, zero-to-working guide.

> If you clone this project onto a fresh computer, follow this ONE file step-by-step and you will see the entire system working locally.

---

## SECTION 1 — What We Are Going To Run

This project contains **5 components** that work together:

```
1. Frontend      — Next.js dashboard (port 3000)
2. Backend       — Express.js API gateway (port 4000)
3. AI Engine     — Python FastAPI analysis service (port 8000)
4. Database      — PostgreSQL (port 5432)
5. LLM Provider  — Groq API (cloud-hosted, no local install needed)
```

### Architecture

```
                  USER (Browser)
                       |
                       v
                  FRONTEND (:3000)
                       |
                       v
                  BACKEND (:4000)
                  /          \
                 v            v
          AI ENGINE (:8000)   DATABASE (:5432)
                 |
                 v
          GROQ CLOUD LLM (api.groq.com)
```

- **Frontend** sends user actions (upload, scan) to Backend
- **Backend** orchestrates everything: stores data in Database, calls AI Engine
- **AI Engine** reads source code from shared workspace, calls Groq LLM for analysis
- **Database** stores repositories, scans, vulnerabilities, patches, feedback
- **Groq API** provides the LLM intelligence (cloud-hosted, you need a free API key)

---

## SECTION 2 — Prerequisites

You need these installed before starting:

### 1. Git

**What**: Version control system to clone the project.

**Check**:
```bash
git --version
```

**Install** (if missing):
- Windows: Download from https://git-scm.com/download/win
- Mac: `brew install git`
- Linux: `sudo apt install git`

---

### 2. Node.js (version 20 or higher)

**What**: JavaScript runtime for Backend and Frontend.

**Check**:
```bash
node --version
```

Must show `v20.x.x` or higher.

**Install** (if missing):
- Download from https://nodejs.org/ (LTS version)
- This also installs `npm`

---

### 3. npm (comes with Node.js)

**What**: Package manager for installing JavaScript dependencies.

**Check**:
```bash
npm --version
```

---

### 4. Python (version 3.11 or higher)

**What**: Runtime for the AI Engine.

**Check**:
```bash
python --version
```

Must show `Python 3.11.x` or higher.

**Install** (if missing):
- Download from https://www.python.org/downloads/
- **Windows**: CHECK the box "Add Python to PATH" during install

---

### 5. pip (comes with Python)

**What**: Package manager for installing Python dependencies.

**Check**:
```bash
pip --version
```

---

### 6. Docker Desktop

**What**: Runs the PostgreSQL database in a container (easiest way to get a database running).

**Check**:
```bash
docker --version
docker compose version
```

**Install** (if missing):
- Download from https://www.docker.com/products/docker-desktop/
- Windows: Requires WSL2 (Docker Desktop installer will set this up)

---

### 7. Groq API Key (free)

**What**: Provides the LLM intelligence for code analysis. Cloud-hosted — nothing to install.

**Get one**:
1. Go to https://console.groq.com
2. Sign up (free)
3. Go to API Keys section
4. Click "Create API Key"
5. Copy the key (starts with `gsk_...`)

---

### Summary Checklist

| Tool | Required Version | Check Command | Install From |
|------|-----------------|---------------|--------------|
| Git | Any | `git --version` | git-scm.com |
| Node.js | 20+ | `node --version` | nodejs.org |
| npm | 10+ | `npm --version` | Comes with Node.js |
| Python | 3.11+ | `python --version` | python.org |
| pip | Latest | `pip --version` | Comes with Python |
| Docker | 24+ | `docker --version` | docker.com |
| Docker Compose | v2+ | `docker compose version` | Comes with Docker Desktop |
| Groq API Key | - | - | console.groq.com |

---

## SECTION 3 — Clone the Project

Open a terminal (PowerShell on Windows) and run:

```bash
git clone <your-repository-url>
cd HalluciShield
```

Replace `<your-repository-url>` with the actual Git URL of this project.

---

## SECTION 4 — Project Structure

After cloning, the project looks like this:

```
HalluciShield/
├── frontend/                # Next.js dashboard (React, TypeScript)
│   ├── app/
│   │   ├── page.tsx         # Main dashboard page
│   │   ├── layout.tsx       # Root layout
│   │   └── components/
│   │       ├── UploadPortal.tsx      # File upload component
│   │       └── ExperimentAnalytics.tsx
│   ├── package.json         # Frontend dependencies
│   ├── next.config.js       # Next.js configuration
│   └── Dockerfile
│
├── backend/                 # Express.js API (TypeScript)
│   ├── src/
│   │   ├── index.ts         # Server entry point
│   │   ├── app.ts           # Express app setup
│   │   ├── config/
│   │   │   ├── env.ts       # Environment variable loading
│   │   │   └── db.ts        # PostgreSQL connection pool
│   │   ├── routes/
│   │   │   ├── health.router.ts
│   │   │   ├── repository.router.ts    # Upload endpoint
│   │   │   └── orchestration.router.ts # Scan endpoints
│   │   ├── services/
│   │   │   ├── upload.service.ts
│   │   │   ├── workspace.service.ts
│   │   │   ├── orchestration.service.ts
│   │   │   └── aiEngine.client.ts
│   │   └── db/
│   │       ├── schema.sql   # Database schema
│   │       ├── migrate.ts   # Migration runner
│   │       └── seed.ts      # Seed data
│   ├── package.json         # Backend dependencies
│   ├── tsconfig.json        # TypeScript config
│   └── Dockerfile
│
├── ai-engine/               # Python FastAPI service
│   ├── app/
│   │   ├── main.py          # FastAPI entry point
│   │   ├── config.py        # Settings (reads .env)
│   │   ├── security.py      # Security utilities
│   │   └── api/             # API route modules
│   │       ├── health.py
│   │       ├── hallucination.py
│   │       ├── security.py
│   │       ├── dependency.py
│   │       └── risk.py
│   │   └── agents/          # Analysis agents
│   │       ├── hallucination_agent.py
│   │       ├── security_agent.py
│   │       ├── dependency_agent.py
│   │       └── risk_engine.py
│   ├── requirements.txt     # Python dependencies
│   └── Dockerfile
│
├── sandbox/                 # Isolated patch validation
│   ├── Dockerfile.sandbox
│   └── runner.py
│
├── docker-compose.yml       # Multi-service orchestration
├── .env.example             # Environment variable template
├── .env                     # Your actual environment (git-ignored)
└── package.json             # Root monorepo scripts
```

---

## SECTION 5 — Environment Variables

### Step 1: Create your .env file

```bash
cp .env.example .env
```

### Step 2: Edit .env

Open `.env` in VS Code and fill in the values.

Here is the **complete .env file** with explanations:

```env
# ============================================================
# SYSTEM
# ============================================================
NODE_ENV=development
PORT=4000
HOST=0.0.0.0

# ============================================================
# BACKEND
# ============================================================
BACKEND_PORT=4000
BACKEND_URL=http://localhost:4000

# ============================================================
# AI ENGINE
# ============================================================
AI_ENGINE_PORT=8000
AI_ENGINE_URL=http://localhost:8000

# ============================================================
# LLM PROVIDER (Groq)
# Get your key at: https://console.groq.com
# ============================================================
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxxxx    <-- PUT YOUR GROQ KEY HERE
DEFAULT_LLM_MODEL=openai/gpt-oss-20b

# ============================================================
# POSTGRESQL DATABASE
# These values must match what you set in Docker below.
# ============================================================
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=hallucishield_user
POSTGRES_PASSWORD=hallucishield_secure_pass_2026
POSTGRES_DB=hallucishield_db
DATABASE_URL=postgresql://hallucishield_user:hallucishield_secure_pass_2026@localhost:5432/hallucishield_db

# ============================================================
# FRONTEND
# ============================================================
NEXT_PUBLIC_API_URL=http://localhost:4000
NEXT_PUBLIC_AI_ENGINE_URL=http://localhost:8000

# ============================================================
# DOCKER SANDBOX (for patch validation)
# ============================================================
SANDBOX_DOCKER_IMAGE=hallucishield-sandbox:latest
SANDBOX_MEMORY_LIMIT=512m
SANDBOX_CPU_LIMIT=1.0
```

### What to change

| Variable | Action |
|----------|--------|
| `LLM_API_KEY` | **REPLACE** with your Groq API key |
| `POSTGRES_USER` | Keep as-is (or change if you want) |
| `POSTGRES_PASSWORD` | Keep as-is (or change if you want) |
| `POSTGRES_DB` | Keep as-is |
| `DATABASE_URL` | Keep as-is (must match POSTGRES_USER + POSTGRES_PASSWORD + POSTGRES_DB) |
| Everything else | Keep as-is |

### Security

> **NEVER commit `.env` to Git.** It contains your API key and database passwords. The `.gitignore` file already excludes `.env`.

---

## SECTION 6 — Start PostgreSQL Database

We use Docker to run PostgreSQL (simplest approach):

```bash
docker run -d `
  --name hallucishield-postgres `
  -e POSTGRES_USER=hallucishield_user `
  -e POSTGRES_PASSWORD=hallucishield_secure_pass_2026 `
  -e POSTGRES_DB=hallucishield_db `
  -p 5432:5432 `
  postgres:16-alpine
```

> **Windows PowerShell users**: Use backticks `` ` `` for line continuation (shown above).

**On Linux/Mac**, use backslashes `\` instead:

```bash
docker run -d \
  --name hallucishield-postgres \
  -e POSTGRES_USER=hallucishield_user \
  -e POSTGRES_PASSWORD=hallucishield_secure_pass_2026 \
  -e POSTGRES_DB=hallucishield_db \
  -p 5432:5432 \
  postgres:16-alpine
```

### Verify database is running

```bash
docker ps
```

You should see `hallucishield-postgres` in the list.

```bash
docker exec hallucishield-postgres pg_isready -U hallucishield_user -d hallucishield_db
```

Expected output: `accepting connections`

### Stop database later

```bash
docker stop hallucishield-postgres
```

### Start database again

```bash
docker start hallucishield-postgres
```

### Delete database completely

```bash
docker stop hallucishield-postgres
docker rm hallucishield-postgres
```

---

## SECTION 7 — Install Backend Dependencies

Open a **new terminal** (Terminal 1):

```bash
cd backend
npm install
```

This installs all Node.js packages from `package.json`.

---

## SECTION 8 — Install Frontend Dependencies

Open a **new terminal** (Terminal 2):

```bash
cd frontend
npm install
```

---

## SECTION 9 — Install AI Engine Dependencies

Open a **new terminal** (Terminal 3):

```bash
cd ai-engine
python -m venv .venv
```

**Activate the virtual environment**:

Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```

Windows CMD:
```cmd
.\.venv\Scripts\activate.bat
```

Linux/Mac:
```bash
source .venv/bin/activate
```

You should see `(.venv)` at the start of your terminal prompt.

Then install packages:

```bash
pip install -r requirements.txt
```

---

## SECTION 10 — Start Order

**This order matters.** Start services in this sequence:

```
1. Database (Docker)     — Must be first, backend needs it
2. AI Engine (Python)    — Backend calls this during scans
3. Backend (Node.js)     — Connects to database and AI engine
4. Frontend (Next.js)    — Sends requests to backend
```

---

## SECTION 11 — Terminal-by-Terminal Instructions

### Terminal 1 — Database (already running from Section 6)

If you haven't started it yet:

```bash
docker run -d --name hallucishield-postgres -e POSTGRES_USER=hallucishield_user -e POSTGRES_PASSWORD=hallucishield_secure_pass_2026 -e POSTGRES_DB=hallucishield_db -p 5432:5432 postgres:16-alpine
```

**Expected**: Container starts silently. Verify with `docker ps`.

---

### Terminal 2 — AI Engine

```bash
cd ai-engine
.\.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate      # Linux/Mac

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app --reload-exclude=.venv
```

Do not run `ai-engine\.venv\Scripts\python.exe` while already inside the
`ai-engine` directory. From that directory the PowerShell path is
`\.venv\Scripts\python.exe`; from the repository root it is
`\.\ai-engine\.venv\Scripts\python.exe`.

**Expected output**:

```
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

Leave this terminal running.

---

### Terminal 3 — Backend

```bash
cd backend
npm run dev
```

**Expected output**:

```
[HalluciShield Backend] Server running on http://localhost:4000
[HalluciShield Backend] Health endpoint: http://localhost:4000/api/v1/health
```

You will also see database migration logs:

```
[Migration] Checking database connection...
[Migration] Applying schema.sql...
[Migration] Schema.sql applied successfully.
```

Leave this terminal running.

---

### Terminal 4 — Frontend

```bash
cd frontend
npm run dev
```

The frontend automatically removes stale Next.js build output before starting.
This avoids a Windows/OneDrive `EINVAL: invalid argument, readlink` error when
`.next` contains generated reparse-point entries.

**Expected output**:

```
  ▲ Next.js 14.2.x
  - Local:        http://localhost:3000
  - Environments: .env.local
```

Leave this terminal running.

---

## SECTION 12 — Verify Every Service

Before using the application, verify each service works:

### Backend Health

Open browser or run in terminal:

```bash
curl http://localhost:4000/api/v1/health
```

**Expected** (JSON response):

```json
{
  "service": "hallucishield-backend",
  "status": "ok",
  "version": "1.0.0",
  "dependencies": {
    "database": "healthy",
    "aiEngineUrl": "http://localhost:8000"
  }
}
```

If `database` shows `"degraded"`, the database is not running or connection details are wrong.

### AI Engine Health

```bash
curl http://localhost:8000/api/v1/health
```

**Expected** (JSON response):

```json
{
  "service": "hallucishield-ai-engine",
  "status": "ok",
  "version": "1.0.0",
  "llm_config": {
    "provider": "openai_compatible",
    "provider_name": "groq",
    "llm_reachable": true
  }
}
```

If `llm_reachable` is `false`, check your `LLM_API_KEY` in `.env`.

### AI Engine Interactive Docs

Open in browser:

```
http://localhost:8000/docs
```

This shows the FastAPI Swagger UI with all available endpoints.

### Frontend

Open in browser:

```
http://localhost:3000
```

You should see the **HalluciShield AI Dashboard** with:
- Sidebar navigation (Dashboard, Code Upload Portal, etc.)
- Metric cards (Repositories Ingested, Hallucinations Flagged, etc.)
- Service health indicators (green dots if backend/AI engine are running)

### Database

```bash
docker exec hallucishield-postgres psql -U hallucishield_user -d hallucishield_db -c "\dt"
```

**Expected**: List of tables including `users`, `repositories`, `scans`, `vulnerabilities`, `hallucination_findings`, `patches`, etc.

---

## SECTION 13 — Run the Complete Application

Now that everything is running, here is the end-to-end workflow:

### Step 1: Open the Frontend

```
http://localhost:3000
```

### Step 2: Upload a Repository

1. Click **"Code Upload Portal"** in the sidebar
2. Drag and drop a `.zip` file containing source code
   - OR click "browse files" and select a `.zip` file
3. Wait for the upload to complete
4. You will see "INGESTED" status with repository details:
   - Repository ID
   - Primary Language
   - File Count
   - Workspace Location

### Step 3: Trigger a Scan

Click the **"Trigger Multi-Agent Vulnerability Scan"** button.

This sends the repository through the analysis pipeline.

### Step 4: Check Scan Results via API

```bash
# Replace <repo-id> with the actual ID from the upload response
# Replace <scan-id> with the scan ID from the scan response

# Check scan status
curl http://localhost:4000/api/repositories/<repo-id>/scan/<scan-id>/status

# Get full findings (after scan completes)
curl http://localhost:4000/api/repositories/<repo-id>/scan/<scan-id>/findings
```

### What happens during a scan:

```
Frontend sends scan request
        |
        v
Backend creates scan record
        |
        v
Backend calls AI Engine:
  1. POST /api/v1/hallucination/detect  (finds phantom methods, invalid imports)
  2. POST /api/v1/security/scan          (finds SQL injection, XSS, etc.)
  3. POST /api/v1/dependency/analyze     (validates packages against registries)
        |
        v
AI Engine reads source files from shared workspace
AI Engine calls Groq LLM for analysis
AI Engine returns findings to Backend
        |
        v
Backend stores results and returns to Frontend
        |
        v
Frontend displays results
```

---

## SECTION 14 — Complete End-to-End Example

Here is what happens when you upload a Python project with a SQL injection vulnerability:

### Input
A `.zip` file containing:
```
my-project/
├── app.py          (contains: cursor.execute("SELECT * FROM users WHERE id=" + user_id))
├── requirements.txt (contains: requests==2.31.0)
└── test_app.py
```

### Pipeline Stages

**Stage 1: Upload**
- Frontend sends `.zip` to `POST http://localhost:4000/api/repositories/upload`
- Backend extracts files to workspace
- Returns `repositoryId`

**Stage 2: Scan Initiation**
- Frontend sends `POST http://localhost:4000/api/repositories/<id>/scan`
- Backend generates `scanId`, materializes workspace
- Returns `202 Accepted` with `scanId`

**Stage 3: Hallucination Detection**
- Backend calls `POST http://localhost:8000/api/v1/hallucination/detect`
- AI Engine reads source files, calls Groq LLM
- Returns: No hallucinations found (or phantom methods if present)

**Stage 4: Security Scanning**
- Backend calls `POST http://localhost:8000/api/v1/security/scan`
- AI Engine runs Semgrep rules + LLM analysis
- Returns: SQL injection vulnerability found at `app.py:3`

**Stage 5: Dependency Analysis**
- Backend calls `POST http://localhost:8000/api/v1/dependency/analyze`
- AI Engine checks `requests==2.31.0` against PyPI
- Returns: Package exists, version available

**Stage 6: Risk Assessment**
- Backend aggregates all findings
- Calculates risk level
- Stores in database

**Stage 7: Results Displayed**
- Frontend shows vulnerability findings
- Shows risk score
- Offers patch generation option

---

## SECTION 15 — Expected Output

### Terminal — AI Engine

```
INFO:     Started server process [xxxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     127.0.0.1:xxxxx - "POST /api/v1/hallucination/detect HTTP/1.1" 200 OK
INFO:     127.0.0.1:xxxxx - "POST /api/v1/security/scan HTTP/1.1" 200 OK
INFO:     127.0.0.1:xxxxx - "POST /api/v1/dependency/analyze HTTP/1.1" 200 OK
```

### Terminal — Backend

```
[HalluciShield Backend] Server running on http://localhost:4000
[Migration] Schema.sql applied successfully.
[req xxxxxxxx-xxxx] POST /api/repositories/upload -> 201 (xxxms)
[req xxxxxxxx-xxxx] POST /api/repositories/<id>/scan -> 202 (xxxms)
```

### Browser — Frontend

- Dashboard loads with navigation sidebar
- Health indicators show green for Backend and AI Engine
- Upload Portal accepts `.zip` files
- After upload: shows "INGESTED" status card
- After scan: shows vulnerability findings

### Browser — AI Engine Docs

```
http://localhost:8000/docs
```

- Swagger UI with all 30+ endpoints
- Can test endpoints directly from the browser

---

## SECTION 16 — How to Stop the Project

### Stop Frontend (Terminal 4)

Press `Ctrl + C` in the frontend terminal.

### Stop Backend (Terminal 3)

Press `Ctrl + C` in the backend terminal.

### Stop AI Engine (Terminal 2)

Press `Ctrl + C` in the AI Engine terminal.

### Stop Database

```bash
docker stop hallucishield-postgres
```

### Stop Everything at Once (if using Docker Compose)

```bash
docker compose down
```

---

## SECTION 17 — How to Restart the Project

```bash
# 1. Start database (if stopped)
docker start hallucishield-postgres

# 2. Start AI Engine (Terminal 2)
cd ai-engine
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app --reload-exclude=.venv

# 3. Start Backend (Terminal 3)
cd backend
npm run dev

# 4. Start Frontend (Terminal 4)
cd frontend
npm run dev
```

---

## SECTION 18 — Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `npm install` fails | Wrong Node version | Install Node.js 20+ from nodejs.org |
| Port 4000 already in use | Another process using it | See "Kill Process on Port" below |
| Port 5432 already in use | Another PostgreSQL running | Stop other PostgreSQL or change port |
| `DATABASE_URL` connection refused | Database not running | `docker start hallucishield-postgres` |
| `database: "degraded"` in health | Wrong DB credentials | Check POSTGRES_USER/PASSWORD in `.env` and match Docker command |
| AI Engine won't start | Missing dependencies | Run `pip install -r requirements.txt` again |
| `ModuleNotFoundError` | Virtual env not activated | Run `..\.venv\Scripts\Activate.ps1` from the `ai-engine` directory before starting AI Engine |
| `llm_reachable: false` | Bad API key | Get new key from console.groq.com, update `.env` |
| Upload returns 413 | File too large | Max size is 50MB. Compress your archive |
| Upload returns 400 "Invalid archive" | Not a valid .zip | Re-create archive: `zip -r myproject.zip ./myproject/` |
| CORS error in browser | Frontend URL not in CORS_ORIGINS | Add `http://localhost:3000` to CORS_ORIGINS in `.env` |
| `EACCES permission denied` | File permission issue | Run `npm install` from project root, not as admin |
| Frontend shows "Upload Error" | Backend not running | Start backend first: `cd backend && npm run dev` |
| Scan stuck in "RUNNING" | AI Engine too slow or crashed | Check AI Engine terminal for errors |
| `next build` fails | Outdated dependencies | Delete `node_modules`, run `npm install` again |

### Kill a Process on a Port (Windows)

```powershell
# Find process using port 4000
netstat -ano | findstr :4000

# Kill it (replace PID with the number found above)
taskkill /PID <PID> /F
```

### Kill a Process on a Port (Linux/Mac)

```bash
# Find process
lsof -i :4000

# Kill it
kill <PID>
```

---

## SECTION 19 — Windows-Specific Notes

### Python Virtual Environment

If `.\.venv\Scripts\Activate.ps1` gives an execution policy error:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then try activating again.

### Line Continuation in PowerShell

Use backticks `` ` `` instead of backslashes `\`:

```powershell
docker run -d `
  --name hallucishield-postgres `
  -p 5432:5432 `
  postgres:16-alpine
```

### Path Issues

If you see errors about paths with spaces, make sure your project is in a path without spaces (e.g., `C:\Projects\HalluciShield` not `C:\My Projects\HalluciShield`).

---

## SECTION 20 — Linux/macOS Notes

### Python Virtual Environment

```bash
source .venv/bin/activate
```

### Docker Line Continuation

Use backslashes `\`:

```bash
docker run -d \
  --name hallucishield-postgres \
  -p 5432:5432 \
  postgres:16-alpine
```

### File Permissions

If you get permission errors:

```bash
sudo chown -R $USER:$USER ./backend/uploads
```

---

## SECTION 21 — Using Docker Compose (Alternative)

Instead of running services manually, you can use Docker Compose to start everything:

```bash
docker compose up --build
```

This starts all 4 services (database, backend, AI engine, frontend) in containers.

### Stop Docker Compose

```bash
docker compose down
```

### Stop and Delete Data

```bash
docker compose down -v
```

### View Logs

```bash
docker compose logs -f
```

### Restart Single Service

```bash
docker compose restart backend
```

---

## SECTION 22 — Running Tests

### Backend Tests (58 tests)

```bash
cd backend
npm test
```

### AI Engine Tests (810 tests)

```bash
cd ai-engine
.\.venv\Scripts\Activate.ps1
python -m pytest tests/ -v
```

### Frontend Tests

```bash
cd frontend
npm test
```

### All Tests at Once

```bash
npm run test:all
```

---

# QUICK START — COPY & FOLLOW

For those who want the shortest path:

### Step 1: Configure

```bash
cp .env.example .env
```

Edit `.env` — put your Groq API key in `LLM_API_KEY`.

### Step 2: Database

```powershell
docker run -d --name hallucishield-postgres -e POSTGRES_USER=hallucishield_user -e POSTGRES_PASSWORD=hallucishield_secure_pass_2026 -e POSTGRES_DB=hallucishield_db -p 5432:5432 postgres:16-alpine
```

### Step 3: Install dependencies (3 terminals)

**Terminal 1**:
```bash
cd backend
npm install
```

**Terminal 2**:
```bash
cd frontend
npm install
```

**Terminal 3**:
```bash
cd ai-engine
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Step 4: Start services (4 terminals)

**Terminal 1 — Backend**:
```bash
cd backend
npm run dev
```

**Terminal 2 — Frontend**:
```bash
cd frontend
npm run dev
```

**Terminal 3 — AI Engine**:
```bash
cd ai-engine
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload --reload-dir app --reload-exclude=.venv
```

### Step 5: Open browser

```
http://localhost:3000
```

### Step 6: Verify

```bash
curl http://localhost:4000/api/v1/health     # Backend OK
curl http://localhost:8000/api/v1/health     # AI Engine OK
```

### Step 7: Use it

1. Upload a `.zip` file containing source code
2. Click "Trigger Multi-Agent Vulnerability Scan"
3. View results

---

## Final Verification Checklist

| Check | Command/URL | Expected |
|-------|-------------|----------|
| Backend running | `curl http://localhost:4000/api/v1/health` | `"status": "ok"` |
| AI Engine running | `curl http://localhost:8000/api/v1/health` | `"status": "ok"` |
| Frontend running | Open `http://localhost:3000` | Dashboard loads |
| Database running | `docker exec hallucishield-postgres pg_isready` | `accepting connections` |
| LLM connected | Check AI Engine health `llm_reachable` | `true` |
| Schema applied | `docker exec hallucishield-postgres psql -U hallucishield_user -d hallucishield_db -c "\dt"` | List of tables |
| Upload works | Upload `.zip` via frontend | `"status": "INGESTED"` |
| Scan works | Click "Trigger Scan" | Findings returned |
