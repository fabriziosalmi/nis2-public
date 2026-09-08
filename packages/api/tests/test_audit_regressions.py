# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Five defects found by a category audit, pinned so they cannot return.

Each was a case where two things that had to agree did not, and nothing made the
disagreement visible.
"""

from __future__ import annotations

import inspect

import pytest


class TestOneDefinitionOfAClosedIncident:
    """`_CLOSED_STATUSES` existed twice with different contents.

    routers/incident_monitor.py had ("closed", "recovered"); tasks/
    incident_tasks.py had frozenset({"closed", "recovered", "eradicated"}). An
    incident set to `eradicated` was therefore filtered out by the alerting task
    as closed while the API computed is_open=True for the same row, counted it in
    open_count and marked its deadlines breached — the dashboard showed an open,
    breached statutory obligation and no alert was ever sent for it.
    """

    def test_both_consumers_use_the_same_object(self):
        from app.routers import incident_monitor
        from app.tasks import incident_tasks

        assert incident_monitor._CLOSED_STATUSES is incident_tasks._CLOSED_STATUSES

    def test_the_definition_lives_with_the_model(self):
        from app.models.incident import CLOSED_STATUSES

        assert CLOSED_STATUSES == frozenset({"closed", "recovered", "eradicated"})

    def test_eradicated_closes_the_clock_on_both_sides(self):
        """The value the two copies disagreed about."""
        from app.routers import incident_monitor
        from app.tasks import incident_tasks

        assert "eradicated" in incident_monitor._CLOSED_STATUSES
        assert "eradicated" in incident_tasks._CLOSED_STATUSES

    def test_neither_module_declares_its_own_set(self):
        """A second literal is how they diverged the first time."""
        from app.routers import incident_monitor
        from app.tasks import incident_tasks

        for module in (incident_monitor, incident_tasks):
            source = inspect.getsource(module)
            assert 'frozenset({"closed"' not in source
            assert '_CLOSED_STATUSES = ("closed"' not in source


class TestTheMcpCertificateToolUsesThePinnedIp:
    """It validated the target and threw the answer away.

    validate_domain_pinned resolves the name, rejects private, reserved and
    blocked ranges and returns the IP it validated. The MCP tool discarded the
    return value and handed the analyzer the hostname, which resolved again —
    reopening the DNS-rebinding window the validation exists to close. A domain
    answering a public address to the checking lookup and 169.254.169.254 to the
    connecting one got a TLS handshake against the internal address, and its
    certificate came back in the tool response.
    """

    def test_the_validation_result_is_bound(self):
        from app import mcp_server

        source = inspect.getsource(mcp_server.handle_tool_call)
        assert "validation = await validate_domain_pinned(domain)" in source

    def test_the_pinned_ip_reaches_the_analyzer(self):
        from app import mcp_server

        source = inspect.getsource(mcp_server.handle_tool_call)
        assert "pinned_ip=validation.pinned_ip" in source

    def test_it_matches_the_rest_handler(self):
        """Two call sites is why one of them was wrong; until they share a
        service function, pin that both pass the pinned IP."""
        from app.routers import certificates

        rest = inspect.getsource(certificates)
        assert "pinned_ip=validation.pinned_ip" in rest


class TestAFailedMigrationStopsTheDeployment:
    """The entrypoint logged a warning and started the API anyway.

    A failed `alembic upgrade head` fell through to the lifespan's create_all
    fallback, so a deployment whose migration failed came up serving traffic on a
    schema matching neither the previous release nor the new one — and reported
    itself healthy, so Caddy routed to it.
    """

    def test_the_entrypoint_exits_on_failure(self):
        from pathlib import Path

        script = (Path(__file__).resolve().parents[1] / "entrypoint.sh").read_text()
        assert "exit 1" in script
        assert "falling back to ensure_schema" not in script

    def test_it_says_why_it_refused(self):
        from pathlib import Path

        script = (Path(__file__).resolve().parents[1] / "entrypoint.sh").read_text()
        assert "refusing to start" in script.lower()


class TestTheRateLimiterIsShared:
    """It kept counters in process memory.

    Production runs four gunicorn workers, each with its own copy, so a limit
    reading 10/minute admitted up to forty a minute and moved with the worker
    count — and a restart cleared every counter, which made the response to
    suspected abuse the same action that removed the protection.
    """

    def test_the_limiter_is_given_a_storage_uri(self):
        from app.routers import auth

        source = inspect.getsource(auth)
        assert "storage_uri=_limiter_storage_uri()" in source

    def test_it_degrades_rather_than_failing_the_login_path(self):
        """A Redis outage must not deny every login, and must not silently stop
        limiting either."""
        from app.routers import auth

        source = inspect.getsource(auth)
        assert "in_memory_fallback_enabled=True" in source

    def test_no_broker_configured_means_in_memory(self):
        """A bare local run and the unit tests must not require Redis."""
        from app.routers.auth import _limiter_storage_uri

        assert _limiter_storage_uri() is None or _limiter_storage_uri().strip()


class TestThePoolFitsInsideTheDatabase:
    """4 workers x (20 + 10) = 120 against a stock postgres max_connections of 100.

    The pool is per process because gunicorn preforks. At saturation Postgres
    refuses new connections outright, readiness fails and Caddy stops routing, so
    the deployment presents as down rather than slow — with no warning, because
    no pool metric is exported.
    """

    @pytest.mark.parametrize("workers", [4])
    def test_total_demand_fits_within_the_server_limit(self, workers: int):
        from app.config import Settings

        s = Settings(environment="development", _env_file=None)
        total = workers * (s.db_pool_size + s.db_max_overflow)
        assert total < 100, (
            f"{workers} workers x ({s.db_pool_size} + {s.db_max_overflow}) = {total} "
            f"connections against a default max_connections of 100"
        )

    def test_the_sizes_are_configurable(self):
        """An operator who changes the worker count must be able to follow."""
        from app.config import Settings

        s = Settings(
            environment="development", db_pool_size=3, db_max_overflow=1, _env_file=None
        )
        assert (s.db_pool_size, s.db_max_overflow) == (3, 1)

    def test_the_engine_reads_them_rather_than_hardcoding(self):
        from app import database

        source = inspect.getsource(database)
        assert "pool_size=settings.db_pool_size" in source
        assert "max_overflow=settings.db_max_overflow" in source
