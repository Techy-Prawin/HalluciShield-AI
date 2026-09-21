"""
Security utilities for the HalluciShield AI Engine.
DEPRECATED: Use app.security instead. Kept for backward compatibility.
"""

import logging
import os
import pathlib

logger = logging.getLogger(__name__)

_WORKSPACE_BASE: pathlib.Path = pathlib.Path(
    os.getenv("WORKSPACE_BASE_PATH", "/uploads/extracted")
).resolve()


def validate_workspace_path(path: str) -> str:
    """
    Validate workspace path. Delegates to app.security for path traversal prevention.
    """
    from app.security import validate_workspace_path as _secure_validate
    return _secure_validate(path)
