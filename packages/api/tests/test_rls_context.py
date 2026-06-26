# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""H5: set_rls_org_context sets the worker's RLS org context session-scoped
(survives the multiple commits a task issues) and no-ops when no org is given."""
import asyncio
from unittest.mock import AsyncMock

from app.database import set_rls_org_context


def test_sets_org_session_scoped():
    db = AsyncMock()
    asyncio.run(set_rls_org_context(db, "org-123"))
    sqls = [str(c.args[0]) for c in db.execute.call_args_list]
    assert any("app.current_org_id" in s for s in sqls)
    # is_local => false: session-scoped so it isn't cleared by the task's commits.
    assert any("false" in s for s in sqls)
    assert all("true" not in s for s in sqls)


def test_sets_user_when_given():
    db = AsyncMock()
    asyncio.run(set_rls_org_context(db, "org-1", user_id="user-9"))
    sqls = " ".join(str(c.args[0]) for c in db.execute.call_args_list)
    assert "app.current_org_id" in sqls and "app.current_user_id" in sqls


def test_noop_when_org_none():
    db = AsyncMock()
    asyncio.run(set_rls_org_context(db, None))
    db.execute.assert_not_called()
