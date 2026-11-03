"""get_db must commit before the response is sent.

FastAPI runs the exit code of a yield dependency AFTER the response has been
sent unless the dependency is declared with scope="function". get_db commits
in that exit code, so with the default scope a client could receive a 2xx for
a write and read the old state on its next request, before the commit landed
(seen in E2E as a password change answered 204 whose new password was then
rejected with 401).
"""
import ast
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.database import get_db

APP_DIR = Path(__file__).resolve().parent.parent / "app"


def _get_db_depends_calls():
    """Every Depends(get_db, ...) call in app/, found by parsing the source.

    Parsing rather than walking app.routes: FastAPI's included-router objects
    are internal and change between releases, the source does not.
    """
    for path in sorted(APP_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", None)) == "Depends"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "get_db"
            ):
                yield path.relative_to(APP_DIR.parent), node


def test_every_get_db_dependency_is_function_scoped():
    found = 0
    wrong = []
    for rel, call in _get_db_depends_calls():
        found += 1
        scope = next((k.value for k in call.keywords if k.arg == "scope"), None)
        if not (isinstance(scope, ast.Constant) and scope.value == "function"):
            wrong.append(f"{rel}:{call.lineno}")
    assert found > 0, "no Depends(get_db) found: the scan is broken"
    assert not wrong, (
        'Depends(get_db) without scope="function" commits after the response '
        "is sent: " + ", ".join(wrong)
    )


def test_function_scope_commits_before_the_response_is_sent():
    """Pins the FastAPI behaviour the fix relies on."""
    events = []

    async def fake_db():
        yield None
        events.append("commit")

    app = FastAPI()

    @app.middleware("http")
    async def mark_response(request, call_next):
        response = await call_next(request)
        events.append("response")
        return response

    @app.post("/write")
    async def write(db=Depends(get_db, scope="function")):
        return {"ok": True}

    app.dependency_overrides[get_db] = fake_db
    assert TestClient(app).post("/write").status_code == 200
    assert events == ["commit", "response"]
