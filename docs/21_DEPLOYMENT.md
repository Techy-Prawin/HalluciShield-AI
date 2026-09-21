# 21 - Deployment

## Docker Compose (Development)

```bash
docker-compose up --build
```

Starts all four services with shared workspace volume.

## Production Considerations

### Environment Variables

Set in production:
- `DATABASE_URL` - Production PostgreSQL (Neon, RDS, etc.)
- `LLM_API_KEY` - Groq API key
- `JWT_SECRET` - Strong random secret
- `HALLUCISHIELD_API_KEY` - API key for endpoint auth
- `ENVIRONMENT=production`

### Database

- Use managed PostgreSQL (Neon, AWS RDS, etc.)
- Enable SSL connections
- Run schema migrations before starting
- Set up automated backups

### Security

1. **API Key Authentication**: Set `HALLUCISHIELD_API_KEY` to require `X-API-Key` header
2. **CORS**: Configure `CORS_ORIGINS` for your domain
3. **Rate Limiting**: Adjust `RATE_LIMIT_MAX_REQUESTS` as needed
4. **HTTPS**: Use reverse proxy (nginx, Caddy) for TLS termination

### Scaling

- Backend: Horizontal scaling (stateless, in-memory scan registry)
- AI Engine: Horizontal scaling (stateless agents)
- Frontend: Static export or CDN
- Database: Connection pooling (already configured: max 10)

### Monitoring

- Health endpoints: `GET /api/v1/health`
- Request tracing: `X-Request-ID` header
- Logging: Structured logs with request IDs

## Manual Deployment

### Backend

```bash
cd backend
npm ci --production
npm run build
NODE_ENV=production node dist/index.js
```

### AI Engine

```bash
cd ai-engine
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Frontend

```bash
cd frontend
npm ci
npm run build
npm start
```

## Docker Production

```bash
# Build and start
docker-compose -f docker-compose.yml up -d --build

# View logs
docker-compose logs -f

# Restart single service
docker-compose restart backend

# Stop
docker-compose down
```

## Health Checks

```bash
# Backend
curl -f http://localhost:4000/api/v1/health || exit 1

# AI Engine
curl -f http://localhost:8000/api/v1/health || exit 1
```

## Backup

```bash
# Database backup
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql

# Workspace backup
docker cp hallucishield_backend:/workspace ./workspace_backup
```
