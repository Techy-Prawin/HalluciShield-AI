# 24 - Developer Guide

## Getting Started

1. Clone the repository
2. Copy `.env.example` to `.env`
3. Start with Docker Compose: `docker-compose up --build`
4. Open `http://localhost:3000`

## Project Structure

```
HalluciShield/
├── frontend/             # Next.js dashboard
├── backend/              # Express API gateway
├── ai-engine/            # FastAPI analysis service
├── sandbox/              # Docker validation runtime
├── docs/                 # This documentation
├── docker-compose.yml    # Service orchestration
└── .env.example          # Environment template
```

## Code Style

### TypeScript (Backend/Frontend)

- Use strict TypeScript
- Prefer `interface` over `type` for object shapes
- Use `const` by default, `let` when reassignment needed
- No `var`
- Use async/await over callbacks

### Python (AI Engine)

- Follow PEP 8
- Use type hints
- Use docstrings for public functions
- Prefer f-strings over `.format()`

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

Follow existing code patterns and conventions.

### 3. Run Tests

```bash
# Backend
cd backend && npm test

# AI Engine
cd ai-engine && python -m pytest tests/ -v

# Frontend
cd frontend && npm test
```

### 4. Verify Services

```bash
docker-compose up --build
curl http://localhost:4000/api/v1/health
curl http://localhost:8000/api/v1/health
```

### 5. Submit PR

- Include test coverage for new features
- Update documentation if needed
- Follow commit message conventions

## Commit Messages

Use conventional commits:

```
feat: add new hallucination detection category
fix: resolve zip-slip vulnerability in upload
docs: update API specification
test: add workspace isolation tests
refactor: simplify risk engine aggregation
```

## Adding New Features

### New AI Engine Endpoint

1. Create route in `ai-engine/app/api/`
2. Add request/response models in `ai-engine/app/agents/models.py`
3. Implement agent logic in `ai-engine/app/agents/`
4. Register router in `ai-engine/app/main.py`
5. Add tests in `ai-engine/tests/`

### New Backend Route

1. Create router in `backend/src/routes/`
2. Add types in `backend/src/models/types.ts`
3. Register in `backend/src/app.ts`
4. Add tests in `backend/tests/`

### New Database Table

1. Add schema to `backend/src/db/schema.sql`
2. Create model in `backend/src/models/`
3. Add migration to `backend/src/db/migrate.ts`

## Testing Guidelines

### Unit Tests

- Test individual functions/methods
- Mock external dependencies
- Use descriptive test names
- Aim for >80% coverage

### Integration Tests

- Test endpoint workflows
- Use test databases
- Clean up after tests

### Test Naming

```python
# AI Engine
def test_hallucination_agent_detects_phantom_methods():
    ...

# Backend
describe('UploadService', () => {
  it('should reject zip-slip paths', () => {
    ...
  });
});
```

## Security Guidelines

1. **Never commit secrets** - Use `.env` (git-ignored)
2. **Validate inputs** - Always validate workspace paths
3. **Sanitize LLM prompts** - Use `sanitize_for_llm_prompt()`
4. **Use parameterized queries** - Never interpolate SQL
5. **Rate limit endpoints** - Apply rate limiting to public APIs
6. **Log securely** - Never log API keys or secrets

## Documentation

- Update `docs/` for new features
- Keep API specs current
- Document environment variables
- Add troubleshooting entries

## Release Process

1. Update version in `package.json` / `config.py`
2. Update CHANGELOG
3. Create release branch
4. Run full test suite
5. Deploy to staging
6. Verify health endpoints
7. Merge to main
8. Deploy to production
