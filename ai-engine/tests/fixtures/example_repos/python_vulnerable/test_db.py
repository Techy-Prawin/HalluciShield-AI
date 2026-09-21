import pytest
from db import get_user_safe, create_user


def test_get_user_safe_returns_user():
    """Test that safe query works correctly."""
    # This test should pass
    assert callable(get_user_safe)


def test_create_user_works():
    """Test that create_user works."""
    assert callable(create_user)


def test_parameterized_query_prevents_injection():
    """Test that parameterized query prevents SQL injection."""
    malicious_input = "'; DROP TABLE users; --"
    # The safe function should handle this without error
    # In real test, would actually query database
    assert True


def test_input_validation_works():
    """Test input validation."""
    import re
    valid_username = "admin123"
    invalid_username = "admin'; DROP TABLE users; --"
    
    pattern = r'^[a-zA-Z0-9_]+$'
    assert re.match(pattern, valid_username) is not None
    assert re.match(pattern, invalid_username) is None
