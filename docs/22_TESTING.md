# 22 - Testing

## Test Suites

| Suite | Framework | Location | Count |
|-------|-----------|----------|-------|
| Backend | Jest | `backend/tests/` | 58 tests |
| AI Engine | pytest | `ai-engine/tests/` | 810 tests |
| Frontend | Vitest | `frontend/` | Component tests |

## Running Tests

### Backend

```bash
cd backend
npm test
```

Runs Jest with TypeScript support.

### AI Engine

```bash
cd ai-engine
python -m pytest tests/ -v
```

### Frontend

```bash
cd frontend
npm test
```

### All Tests

```bash
npm run test:backend
npm run test:ai
npm run test:frontend
```

## Test Categories

### Backend Tests

**Unit Tests** (`backend/tests/`):
- `upload.test.ts` - Upload flow, zip-slip protection
- `orchestration.test.ts` - Scan lifecycle, agent communication
- `aiEngineClient.test.ts` - AI engine HTTP client
- `health.test.ts` - Health endpoint
- `workspace.test.ts` - Shared workspace operations

**Integration Tests**:
- Upload → scan → completion flow
- AI engine endpoint mocking
- Database operations

### AI Engine Tests

**Agent Tests**:
- `test_hallucination_agent.py` - Hallucination detection
- `test_security_agent.py` - Security scanning
- `test_dependency_agent.py` - Dependency validation
- `test_analyzer.py` - Code analysis

**Infrastructure Tests**:
- `test_workspace_access.py` - Workspace security
- `test_rate_limiting.py` - Rate limit middleware
- `test_security_utils.py` - Security utilities

**Endpoint Tests**:
- API endpoint validation
- Request/response schemas
- Error handling

### Frontend Tests

**Component Tests**:
- UploadPortal rendering
- User interaction handling
- API communication

## Test Configuration

### Backend (Jest)

`backend/jest.config.js`:
- TypeScript support via `ts-jest`
- Module path aliases
- Coverage collection

### AI Engine (pytest)

`ai-engine/tests/conftest.py`:
- Disables live LLM calls (`chat_json` → `""`)
- Disables rate limiter for tests
- Provides test fixtures

### Frontend (Vitest)

`frontend/vitest.config.ts`:
- React testing library
- JSDOM environment
- CSS module mocking

## Coverage

```bash
# Backend
npm test -- --coverage

# AI Engine
python -m pytest tests/ --cov=app --cov-report=html
```

## Mocking Strategy

### Backend
- AI engine responses mocked in tests
- Database operations use test database
- File system operations use temp directories

### AI Engine
- LLM calls disabled in tests (`conftest.py`)
- HTTP client mocked for registry lookups
- File operations use temp directories

## CI/CD Integration

```yaml
# Example GitHub Actions
- name: Run Backend Tests
  run: cd backend && npm test

- name: Run AI Engine Tests
  run: cd ai-engine && python -m pytest tests/ -v

- name: Run Frontend Tests
  run: cd frontend && npm test
```
