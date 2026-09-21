# 03 - Tech Stack

## Backend (API Gateway & Orchestrator)

| Component | Technology | Version |
|-----------|-----------|---------|
| Runtime | Node.js | 20 LTS |
| Framework | Express | - |
| Language | TypeScript | 5.6.x |
| Database Client | pg (node-postgres) | Pool-based |
| Testing | Jest | - |
| Build | `tsc` (TypeScript Compiler) | - |

**Key libraries**: `multer` (file uploads), `uuid` (scan IDs), `dotenv` (env config)

## AI Engine (Analysis Service)

| Component | Technology | Version |
|-----------|-----------|---------|
| Runtime | Python | 3.13 |
| Framework | FastAPI | 0.115.x |
| ASGI Server | Uvicorn | 0.34.x |
| HTTP Client | httpx | 0.28.x |
| Settings | pydantic-settings | 2.9.x |
| Testing | pytest + pytest-asyncio | 8.4.x |
| LLM Provider | Groq API | OpenAI-compatible |

**Key dependencies**: `slowapi` (rate limiting), `asyncpg`/`psycopg2-binary` (DB), `SQLAlchemy` (ORM)

## Frontend (Dashboard)

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Next.js | 14.2.x |
| UI Library | React | 18.3.x |
| Language | TypeScript | 5.6.x |
| Charts | Recharts | 3.10.x |
| Testing | Vitest + @testing-library/react | 2.1.x |
| CSS | CSS Modules | - |

## Database

| Component | Technology |
|-----------|-----------|
| Database | PostgreSQL (Neon cloud) |
| Schema | UUID primary keys, JSONB metadata |
| Migrations | `backend/src/db/migrate.ts` |
| Schema Definition | `backend/src/db/schema.sql` |

## Infrastructure

| Component | Technology |
|-----------|-----------|
| Containerization | Docker + Docker Compose v2 |
| Orchestration | docker-compose.yml |
| Shared Storage | Named Docker volume (`hallucishield_workspace`) |
| Sandbox | Isolated Docker container (Python 3.11-slim) |
| Security Scanner | Semgrep (in sandbox) |

## Development Tools

| Tool | Purpose |
|------|---------|
| npm | Backend/frontend dependency management |
| pip | AI engine dependency management |
| TypeScript | Type safety across backend/frontend |
| Vitest | Frontend unit tests |
| Jest | Backend unit tests |
| pytest | AI engine unit tests |
