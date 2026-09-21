FROM python:3.11-slim

WORKDIR /app

COPY ai-engine/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY ai-engine/app ./app
COPY ai-engine/pytest.ini ./pytest.ini
COPY ai-engine/tests ./tests
COPY sandbox ./sandbox

# Shared workspace volume mount point: created so the named volume is seeded
# with a writable, correctly-owned directory shared with the backend container.
RUN mkdir -p /workspace/runs /workspace/archives

EXPOSE 8000

ENV PORT=8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
