# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The SUPERUSER/BYPASSRLS guard must actually stop a boot.

Postgres bypasses Row Level Security for SUPERUSER and BYPASSRLS roles, and
FORCE ROW LEVEL SECURITY does not bind them either. So when the runtime role has
either attribute, every `tenant_isolation` policy on the database is decorative
and multi-tenant separation rests on application-layer org_id filters alone --
one forgotten WHERE clause from cross-tenant exposure, on a platform sold for
managing several clients in one instance.

`assert_db_role_rls_safe()` exists to refuse to serve in that state. It was
written, documented and unit-tested, and it had never once stopped a boot:

  * it was called from the tail of `setup_row_level_security()`;
  * `main.py`'s lifespan wrapped that call in `try/except Exception`, because
    policy setup is legitimately best-effort;
  * so the guard's RuntimeError was swallowed by that handler and the API
    carried on serving with RLS bypassed, having logged a traceback.

Meanwhile `tasks/celery_app.py` called the same function directly and did
`sys.exit(1)` -- so the API and the worker of the same system ran on different
security postures, and a comment in the worker described the API as "the same
loud, restart-looping failure", which the API did not have.

Nothing tested the wiring, only the function. These tests cover the wiring.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path

import pytest

import app.database as db_module
import app.main as main_module

API_ROOT = Path(__file__).resolve().parents[1]


def _function_tree(fn) -> ast.AST:
    """Parse a function's own source into an AST.

    `inspect.cleandoc` is for docstrings and mangles indented source; a
    decorated coroutine also carries its decorator line. textwrap.dedent plus a
    tolerant parse handles both.
    """
    source = textwrap.dedent(inspect.getsource(fn))
    return ast.parse(source)


class TestGuardIsNotSwallowed:
    """Structural assertions on the lifespan.

    The failure was a *placement* bug: correct function, wrong side of an
    exception handler. Structure is therefore what has to be pinned, and the
    cheapest honest way to pin it is to read the AST of the lifespan and check
    that the guard call is not nested inside a `try` that catches broadly.
    """

    @staticmethod
    def _lifespan_tree() -> ast.AST:
        return _function_tree(main_module.lifespan)

    def test_lifespan_calls_the_guard(self):
        calls = {
            node.func.id
            for node in ast.walk(self._lifespan_tree())
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "assert_db_role_rls_safe" in calls, (
            "lifespan no longer calls assert_db_role_rls_safe — the production "
            "SUPERUSER/BYPASSRLS refusal is gone"
        )

    def test_guard_call_is_not_inside_a_try_block(self):
        """The regression, stated exactly.

        A call to the guard anywhere inside a `try` whose handler catches
        Exception (or BaseException) is disarmed, because RuntimeError is a
        subclass of Exception. That is precisely how it was disarmed before.
        """
        tree = self._lifespan_tree()

        def _calls_guard(node: ast.AST) -> bool:
            return any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "assert_db_role_rls_safe"
                for n in ast.walk(node)
            )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            catches_broadly = any(
                handler.type is None
                or (
                    isinstance(handler.type, ast.Name)
                    and handler.type.id in {"Exception", "BaseException"}
                )
                for handler in node.handlers
            )
            if not catches_broadly:
                continue
            for stmt in node.body:
                assert not _calls_guard(stmt), (
                    "assert_db_role_rls_safe() is called inside a try block that "
                    "catches Exception. RuntimeError is an Exception, so the "
                    "guard cannot fail closed — this is the exact bug it was "
                    "moved out of setup_row_level_security() to escape."
                )

    def test_setup_rls_no_longer_calls_the_guard(self):
        """Belt and braces: if the call comes back here it is swallowed again,
        because the lifespan legitimately wraps this function in a broad
        except."""
        tree = _function_tree(db_module.setup_row_level_security)
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "assert_db_role_rls_safe" not in calls, (
            "setup_row_level_security() calls the guard again. The lifespan wraps "
            "this function in `except Exception`, so the guard's RuntimeError "
            "would be swallowed and the API would boot with RLS bypassed."
        )


class TestPrivilegedIdentitySplit:
    """The runtime role cannot do DDL, so bootstrap needs a second identity."""

    def test_migration_url_falls_back_to_database_url(self):
        """No configured split == historical single-role behaviour, unchanged."""
        from app.config import Settings

        s = Settings(
            environment="development",
            database_url="postgresql+asyncpg://u:p@h/db",
            database_url_sync="postgresql://u:p@h/db",
            _env_file=None,
        )
        assert s.uses_split_db_identities is False
        assert s.effective_migration_url == s.database_url
        assert s.effective_migration_url_sync == s.database_url_sync

    def test_migration_url_overrides_when_configured(self):
        from app.config import Settings

        s = Settings(
            environment="development",
            database_url="postgresql+asyncpg://nis2_app:p@h/db",
            migration_database_url="postgresql+asyncpg://nis2:s@h/db",
            _env_file=None,
        )
        assert s.uses_split_db_identities is True
        assert s.effective_migration_url == "postgresql+asyncpg://nis2:s@h/db"
        assert "nis2_app" in s.database_url

    def test_guard_checks_the_runtime_engine_not_the_privileged_one(self):
        """The whole point is auditing the identity the API actually serves on.

        Asserting against the privileged engine would always pass — it is
        supposed to be a superuser — and would report a safe posture while the
        runtime role was unconstrained.
        """
        source = inspect.getsource(db_module.assert_db_role_rls_safe)
        assert "engine.connect()" in source, (
            "assert_db_role_rls_safe must query the runtime `engine`"
        )
        assert "privileged_engine" not in source, (
            "assert_db_role_rls_safe must NOT run on the privileged engine — that "
            "role is expected to be a superuser, so the check would always pass"
        )

    def test_ddl_paths_use_the_privileged_engine(self):
        """create_all / CREATE POLICY / GRANT need DDL; nis2_app has none."""
        for fn in (db_module.ensure_schema, db_module.setup_row_level_security):
            source = inspect.getsource(fn)
            assert "privileged_engine_scope()" in source, (
                f"{fn.__name__} does not use the privileged engine; under the "
                f"NOSUPERUSER runtime role its DDL fails and is swallowed by a "
                f"warning, leaving the database silently unprovisioned"
            )


class TestInitdbIsActuallyWired:
    """The provisioning script existed for months, mounted by nothing."""

    def test_wrapper_exists_and_is_executable(self):
        wrapper = API_ROOT.parents[1] / "infra/docker/initdb/01-create-app-role.sh"
        assert wrapper.is_file(), "initdb wrapper missing"
        assert wrapper.stat().st_mode & 0o111, (
            "initdb wrapper is not executable — the postgres entrypoint runs .sh "
            "files via the shell but only if they carry the exec bit"
        )

    def test_sql_lives_in_a_subdirectory(self):
        """The entrypoint runs every *.sql in the mounted root with a plain
        `psql -f`, which cannot pass `-v app_pw=...`. A top-level copy would
        abort initialisation on an undefined variable."""
        initdb = API_ROOT.parents[1] / "infra/docker/initdb"
        assert not list(initdb.glob("*.sql")), (
            "a .sql file sits in the initdb root; postgres would run it directly "
            "and fail on the undefined :'app_pw' psql variable"
        )
        assert (initdb / "sql/01-create-app-role.sql").is_file()

    def test_prod_compose_mounts_initdb(self):
        import yaml

        compose = API_ROOT.parents[1] / "infra/docker/docker-compose.prod.yml"
        spec = yaml.safe_load(compose.read_text())
        volumes = spec["services"]["postgres"].get("volumes", [])
        mounts = [v for v in volumes if "docker-entrypoint-initdb.d" in str(v)]
        assert mounts, (
            "docker-compose.prod.yml does not mount infra/docker/initdb into the "
            "postgres container. Without it nis2_app is never created, the API "
            "runs as the bootstrap superuser, and every RLS policy is decorative "
            "— which was true of every deployment of this platform."
        )
        assert any(str(m).endswith(":ro") for m in mounts), (
            "the initdb mount should be read-only"
        )

    @pytest.mark.parametrize("service", ["api", "celery-worker", "celery-beat"])
    def test_prod_compose_pins_production_environment(self, service: str):
        import yaml

        compose = API_ROOT.parents[1] / "infra/docker/docker-compose.prod.yml"
        spec = yaml.safe_load(compose.read_text())
        env = spec["services"][service].get("environment") or {}
        value = (
            env.get("ENVIRONMENT")
            if isinstance(env, dict)
            else next(
                (e.split("=", 1)[1] for e in env if e.startswith("ENVIRONMENT=")), None
            )
        )
        assert value == "production", (
            f"{service} does not pin ENVIRONMENT=production, so a stale .env can "
            f"downgrade it and disable the security controls gated on it"
        )
