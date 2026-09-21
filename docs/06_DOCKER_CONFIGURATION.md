# 06 - Docker Configuration

## docker-compose.yml

Defines four services with a shared workspace volume:

### Services

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `hallucishield-backend` | Custom (backend/Dockerfile) | 4000 | Express API gateway |
| `hallucishield-ai-engine` | Custom (ai-engine/Dockerfile) | 8000 | FastAPI analysis service |
| `hallucishield-frontend` | Custom (frontend/Dockerfile) | 3000 | Next.js dashboard |
| `hallucishield-db` | `postgres:15-alpine` | 5432 | PostgreSQL database |

### Shared Volume

```yaml
volumes:
  hallucishield_workspace:
    driver: local

services:
  backend:
    volumes:
      - hallucishield_workspace:/workspace
    environment:
      - WORKSPACE_ROOT=/workspace

  ai-engine:
    volumes:
      - hallucishield_workspace:/workspace
    environment:
      - HALLUCISHIELD_WORKSPACE_ROOT=/workspace
```

### Networking

All services run on a default Docker bridge network. Backend communicates with AI engine via `http://hallucishield-ai-engine:8000`.

### Backend Dockerfile

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
RUN mkdir -p /workspace/runs /workspace/archives
EXPOSE 4000
CMD ["node", "dist/index.js"]
```

### AI Engine Dockerfile

```dockerfile
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /workspace/runs /workspace/archives
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Frontend Dockerfile

Multi-stage build:
1. **Builder stage**: `npm ci` + `npm run build`
2. **Runner stage**: Copies `.next/standalone` output, runs `node server.js`

### Sandbox Dockerfile

```dockerfile
FROM python:3.11-slim
# Installs Node.js, npm, Java, git, semgrep
# Creates non-root sandboxuser (UID 10001)
# Runs runner.py as validation harness
```

The AI engine Compose build uses the repository root as its context so the
image includes `sandbox/` and can build `hallucishield-sandbox:latest` through
the Docker SDK. Docker Desktop must be running, and the AI engine mounts
`/var/run/docker.sock` to create the isolated validation containers.

Compose sets `SANDBOX_USE_ARCHIVE_TRANSFER=true`. In that mode validation
inputs and `results.json` are transferred through the Docker API instead of
using a temporary path inside the AI engine as a host bind source. This is
necessary because the host Docker daemon cannot see paths that exist only
inside the AI engine container.

## Commands

```bash
# Start all services (Docker Desktop must be running)
docker compose up --build

# Start in background
docker compose up -d

# Stop all services
docker compose down

# View logs
docker-compose logs -f backend
docker-compose logs -f ai-engine

# Rebuild single service
docker-compose up --build backend

# Validate compose file
docker compose config --quiet
```

## Volume Management

```bash
# List volumes
docker volume ls

# Inspect workspace volume
docker volume inspect hallucishield_workspace

# Remove volume (destroys data)
docker-compose down -v
```
