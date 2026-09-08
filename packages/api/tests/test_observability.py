# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""The platform had an excellent audit trail and no telemetry.

Business events were recorded per request into an append-only table with the
actor attached, which answers *who did what*. Nothing answered *whether the
system is working*. The production compose shipped a Prometheus container
scraping three jobs, two of which pointed at `/metrics` endpoints that did not
exist — so a deployment came up two-thirds red, with no application telemetry and
a monitoring system that teaches whoever looks at it to ignore red targets.

There was also no correlation identifier. Four gunicorn workers write to one
stream and a Celery worker writes asynchronously to another, so relating the
records of a single operation was possible only by timestamp and guesswork —
while the machinery to fix it was already present, carrying identity into the
audit table.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.database import get_db
from app.main import create_app


async def _fake_db():
    """DB-free stand-in, as in test_api.py: these tests exercise middleware and
    the metrics endpoint, none of which needs Postgres."""
    yield None


@pytest.fixture
def app():
    application = create_app()
    application.dependency_overrides[get_db] = _fake_db
    return application


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


class TestTheMetricsEndpointExists:
    def test_it_answers(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]

    def test_it_is_where_prometheus_has_always_looked(self):
        """The scrape job predates the endpoint by several releases; the path is
        not ours to choose."""
        import yaml
        from pathlib import Path

        cfg = yaml.safe_load(
            (Path(__file__).resolve().parents[3] / "prometheus.yml").read_text()
        )
        api_job = next(j for j in cfg["scrape_configs"] if j["job_name"] == "nis2-api")
        assert api_job["metrics_path"] == "/metrics"

    def test_no_job_scrapes_something_that_cannot_answer(self):
        """A permanently red target is worse than a missing one."""
        import yaml
        from pathlib import Path

        cfg = yaml.safe_load(
            (Path(__file__).resolve().parents[3] / "prometheus.yml").read_text()
        )
        assert not [j for j in cfg["scrape_configs"] if j["job_name"] == "nis2-web"]

    def test_the_pool_gauges_are_present(self, client):
        """The leading indicator of the failure this deployment is closest to:
        four workers each hold their own pool, and saturation used to arrive with
        no warning at all."""
        body = client.get("/metrics").text
        assert "nis2_db_pool_connections_in_use" in body
        assert "nis2_db_pool_capacity" in body

    def test_requests_are_counted_by_outcome(self, client):
        client.get("/api/v1/health/live")
        body = client.get("/metrics").text
        assert "nis2_http_requests_total" in body
        assert "nis2_http_request_duration_seconds" in body

    def test_the_endpoint_label_is_a_template_not_a_path(self, client):
        """An id in the label is an outage caused by a metric. One series per
        route, not one per resource."""
        client.get("/api/v1/scans/11111111-1111-1111-1111-111111111111")
        client.get("/api/v1/scans/22222222-2222-2222-2222-222222222222")
        body = client.get("/metrics").text
        assert "11111111-1111-1111-1111-111111111111" not in body
        assert "22222222-2222-2222-2222-222222222222" not in body

    def test_rejected_requests_are_counted_too(self, client):
        """An error rate that omits rejections is the one an operator would most
        want during an incident."""
        client.get("/api/v1/scans")  # 401, no credentials
        body = client.get("/metrics").text
        assert 'status="401"' in body


class TestTheRequestIdentifier:
    def test_every_response_carries_one(self, client):
        resp = client.get("/api/v1/health/live")
        assert resp.headers.get("X-Request-Id")

    def test_it_is_returned_so_a_user_can_quote_it(self, client):
        """A user reporting "it failed at 14:02" gave an operator nothing to
        search for."""
        first = client.get("/api/v1/health/live").headers["X-Request-Id"]
        second = client.get("/api/v1/health/live").headers["X-Request-Id"]
        assert first and second and first != second

    def test_a_caller_supplied_identifier_is_reused(self, client):
        """So a request traced through a proxy or an SDK keeps its identity."""
        resp = client.get(
            "/api/v1/health/live", headers={"X-Request-Id": "trace-abc-123"}
        )
        assert resp.headers["X-Request-Id"] == "trace-abc-123"

    @pytest.mark.parametrize(
        "hostile",
        [
            "a\nINJECTED fake log line",
            "b\r\nSet-Cookie: evil=1",
            "c" * 500,
        ],
    )
    def test_a_hostile_identifier_cannot_inject(self, client, hostile: str):
        """This value reaches log lines and a response header, so an unbounded
        or newline-bearing one would be an injection primitive rather than a
        diagnostic aid."""
        resp = client.get("/api/v1/health/live", headers={"X-Request-Id": hostile})
        returned = resp.headers["X-Request-Id"]
        assert "\n" not in returned and "\r" not in returned
        assert len(returned) <= 128

    def test_it_does_not_leak_between_requests(self, client):
        """The identity contextvars had exactly this bug once, fixed by resetting
        the token in a finally block; the request id uses the same discipline."""
        from app.middleware.identity import request_id

        client.get("/api/v1/health/live", headers={"X-Request-Id": "first"})
        assert request_id.get() in (None, "")


class TestLogRecordsCarryTheIdentifier:
    def test_the_filter_attaches_it(self):
        from app.logging_config import RequestIdFilter

        record = logging.LogRecord("x", logging.INFO, "f", 1, "msg", None, None)
        assert RequestIdFilter().filter(record) is True
        assert hasattr(record, "request_id")

    def test_records_outside_a_request_are_marked_as_such(self):
        """Startup lines and beat tasks belong to no request, and saying so is
        more honest than inventing an id for them."""
        from app.logging_config import RequestIdFilter

        record = logging.LogRecord("x", logging.INFO, "f", 1, "msg", None, None)
        RequestIdFilter().filter(record)
        assert record.request_id == "-"

    def test_the_format_includes_it(self):
        from app.logging_config import LOG_FORMAT

        assert "%(request_id)s" in LOG_FORMAT
