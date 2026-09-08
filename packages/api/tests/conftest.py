import sys
import os
import pytest

# Add packages/api to path so tests can import app modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["ENVIRONMENT"] = "development"

from app.routers.auth import limiter

@pytest.fixture(autouse=True)
def disable_rate_limiter():
    """Disable SlowAPI rate limiter globally for tests so they don't hit 429 Too Many Requests."""
    # The limiter's storage is shared and durable now that it is backed by
    # Redis in a real deployment, so a test that re-enables the limiter starts
    # with whatever counters the last run left behind. Reset before and after.
    try:
        limiter.reset()
    except Exception:  # storage unreachable — in-memory fallback, nothing to reset
        pass
    limiter.enabled = False
    yield
    limiter.enabled = True
    try:
        limiter.reset()
    except Exception:
        pass
