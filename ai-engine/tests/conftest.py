import itertools

import pytest

from app.agents import patch_agent, llm_reasoner
from app.agents import llm_client
from app.security import get_client_id


@pytest.fixture(autouse=True)
def disable_live_llm(monkeypatch):
    """
    Keep the test suite hermetic and deterministic: never call a live LLM
    provider during tests. Agents fall back to their deterministic logic,
    which is the same behavior the suite expects offline.
    """
    fake = lambda *args, **kwargs: ""
    monkeypatch.setattr(llm_client, "chat_json", fake)
    monkeypatch.setattr(llm_reasoner, "chat_json", fake)
    monkeypatch.setattr(patch_agent, "chat_json", fake)


@pytest.fixture(autouse=True)
def disable_rate_limiter(monkeypatch):
    """
    The in-memory rate limiter (120 req / 60s per client IP) is shared across
    the whole app instance, so one fast test run can 429-flood endpoint tests.
    Give each request a unique client id: it is timing behavior, not under
    test here. get_client_id is resolved per request, so this bypass always
    takes effect (unlike patching dispatch, which is bound at build time).
    """
    counter = itertools.count()

    def _unique_client_id(request):
        return f"pytest-{next(counter)}"

    monkeypatch.setattr(
        "app.security.get_client_id",
        _unique_client_id,
        raising=False,
    )


@pytest.fixture(autouse=True)
def bypass_api_key_for_tests(monkeypatch):
    """
    Ensure API key auth is disabled during unit tests unless explicitly tested.
    """
    monkeypatch.setenv("HALLUCISHIELD_API_KEY", "")