# 05 - Environment Variables

## `.env` File Location

Place `.env` in the project root. Both backend and AI engine read from it.

## Required Variables

| Variable | Service | Description |
|----------|---------|-------------|
| `DATABASE_URL` | Backend | PostgreSQL connection string (e.g., `postgresql://user:pass@host:5432/db`) |
| `LLM_BASE_URL` | AI Engine | LLM provider base URL (e.g., `https://api.groq.com/openai/v1`) |
| `LLM_API_KEY` | AI Engine | LLM provider API key |

## Backend Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4000` | Backend server port |
| `DATABASE_URL` | - | PostgreSQL connection string |
| `WORKSPACE_ROOT` | `backend/uploads/extracted` | Shared workspace root (set to `/workspace` in Docker) |
| `NODE_ENV` | `development` | Environment mode |

## AI Engine Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_ENGINE_PORT` | `8000` | AI engine server port |
| `LLM_BASE_URL` | - | LLM provider base URL |
| `LLM_API_KEY` | - | LLM provider API key |
| `DEFAULT_LLM_MODEL` | `openai/gpt-oss-20b` | LLM model identifier |
| `HALLUCISHIELD_WORKSPACE_ROOT` | - | Workspace root restriction (set to `/workspace` in Docker) |
| `DATABASE_URL` | `postgresql+asyncpg://...` | Async PostgreSQL connection string |
| `DATABASE_URL_SYNC` | `postgresql://...` | Sync PostgreSQL connection string |
| `JWT_SECRET` | auto-generated (dev) | JWT signing secret (required in production) |
| `CORS_ORIGINS` | `http://localhost:3000` | Allowed CORS origins (comma-separated) |
| `HALLUCISHIELD_API_KEY` | - | Optional API key for endpoint authentication |
| `ENVIRONMENT` | `development` | Environment mode |

## Frontend Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:4000` | Backend API URL for client-side calls |

## Docker Compose Variables

These are set in `docker-compose.yml` and override `.env`:

| Variable | Value | Set On |
|----------|-------|--------|
| `WORKSPACE_ROOT` | `/workspace` | Backend container |
| `HALLUCISHIELD_WORKSPACE_ROOT` | `/workspace` | AI Engine container |

## Security Notes

- **Never commit `.env`** to version control (it's git-ignored)
- `LLM_API_KEY` is never logged or forwarded in API responses
- `JWT_SECRET` must be set explicitly in production
- `HALLUCISHIELD_API_KEY` is optional; when unset, no API key auth is enforced
