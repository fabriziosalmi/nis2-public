import sys
import os
import pytest

# Add packages/api to path so tests can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.routers.auth import limiter

@pytest.fixture(autouse=True)
def disable_rate_limiter():
    """Disable SlowAPI rate limiter globally for tests so they don't hit 429 Too Many Requests."""
    limiter.enabled = False
    yield
    limiter.enabled = True
