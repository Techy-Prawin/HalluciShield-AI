# 23 - Troubleshooting

## Common Issues

### Backend Won't Start

**Symptom**: `Error: listen EADDRINUSE: address already in use :::4000`

**Fix**:
```bash
# Find process using port 4000
lsof -i :4000  # Linux/Mac
netstat -ano | findstr :4000  # Windows

# Kill the process
kill <PID>
```

### Database Connection Refused

**Symptom**: `Error: connect ECONNREFUSED 127.0.0.1:5432`

**Fix**:
1. Ensure PostgreSQL is running
2. Check `DATABASE_URL` in `.env`
3. Verify credentials and database name
4. Test connection: `psql $DATABASE_URL -c "SELECT 1;"`

### AI Engine Won't Start

**Symptom**: `ModuleNotFoundError: No module named 'app'`

**Fix**:
```bash
cd ai-engine
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### LLM API Errors

**Symptom**: `401 Unauthorized` from Groq API

**Fix**:
1. Check `LLM_API_KEY` in `.env`
2. Verify API key is valid at Groq dashboard
3. Ensure `LLM_BASE_URL` is correct: `https://api.groq.com/openai/v1`

### Upload Fails

**Symptom**: `413 Request Entity Too Large`

**Fix**:
- Maximum upload size: 50MB
- Compress your archive before uploading

### Zip-Slip Detection

**Symptom**: `400 Path traversal detected`

**Fix**:
- Archive contains files with `..` in paths
- Re-create the archive without traversal paths
- Use `zip -r` command (not GUI archivers that may add absolute paths)

### Workspace Path Errors

**Symptom**: `403 Path outside allowed workspace root`

**Fix**:
- AI engine cannot access paths outside `HALLUCISHIELD_WORKSPACE_ROOT`
- Ensure workspace path is inside the shared volume
- In Docker, use `/workspace/runs/<scanId>/`

### Scan Stuck in SCANNING

**Symptom**: Scan never completes

**Fix**:
1. Check AI engine logs: `docker-compose logs ai-engine`
2. Verify AI engine is reachable: `curl http://localhost:8000/api/v1/health`
3. Check LLM API connectivity
4. Restart scan: `POST /api/orchestration/cancel/:id`

### Docker Compose Issues

**Symptom**: `Error response from daemon: Conflict`

**Fix**:
```bash
docker-compose down
docker-compose up --build
```

### Permission Denied

**Symptom**: `EACCES: permission denied`

**Fix**:
```bash
# Fix workspace permissions
sudo chown -R $USER:$USER ./backend/uploads
chmod -R 755 ./backend/uploads
```

## Debug Mode

### Backend

```bash
DEBUG=* npm run dev
```

### AI Engine

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level debug
```

### Docker Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f ai-engine
```

## Health Check Commands

```bash
# Backend
curl http://localhost:4000/api/v1/health

# AI Engine
curl http://localhost:8000/api/v1/health

# Database
psql $DATABASE_URL -c "SELECT COUNT(*) FROM users;"

# Docker
docker-compose ps
docker volume ls
```

## Performance Issues

### Slow Uploads

- Check disk I/O on workspace volume
- Verify network speed to backend
- Consider smaller archive sizes

### Slow Scans

- Check LLM API latency
- Verify AI engine resources
- Consider caching registry lookups

### Memory Issues

- Monitor container memory usage
- Check for memory leaks in long-running scans
- Adjust Docker memory limits
