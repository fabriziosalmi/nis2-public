# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Notification channels — the delivery targets for Art. 23 deadline alerts.

Before this router there was no way to create a channel: no endpoint, no seed,
and a settings screen that kept channels in React state, discarded them on
navigation, and raised a success toast anyway. The Celery beat task that
dispatches the 24 h / 72 h / 1-month alerts reads NotificationChannel rows, so
it always found none and fell back to emailing organisation admins — which
needs SMTP configured. With neither, the alert for a legally binding deadline
went to the application log.

These tests cover the properties that keep the feature honest: credentials do
not come back in cleartext, a channel that could never deliver is refused at
write time rather than failing every 15 minutes inside a task, and the
destination keys stay in step with what the dispatcher actually reads.
"""

from __future__ import annotations

import uuid

import pytest

from app.routers.notifications import (
    CHANNEL_TYPES,
    TARGET_KEY_BY_TYPE,
    _redact,
    _validate_config,
)


class _Channel:
    """Stand-in for a NotificationChannel row (no DB needed for _redact)."""

    def __init__(self, channel_type: str, config: dict, name: str = "ch"):
        self.id = uuid.uuid4()
        self.channel_type = channel_type
        self.name = name
        self.config = config
        self.events: list[str] = []
        self.is_active = True


class TestCredentialsAreNotHandedBack:
    """`config` is encrypted at rest (L14) because it holds Slack webhook URLs
    and webhook signing secrets. Returning them in cleartext on every list
    request would undo that: a read-only viewer could harvest them, and they
    would sit in browser memory and any cache in between."""

    def test_webhook_secret_is_masked(self):
        out = _redact(_Channel("webhook", {"url": "https://x.example.com/h", "secret": "s3cr3t"}))
        assert out["config"]["secret"] != "s3cr3t"
        assert "s3cr3t" not in str(out)

    def test_token_is_masked(self):
        out = _redact(_Channel("slack", {"webhook_url": "https://hooks.slack.com/a/b", "token": "xoxb-1"}))
        assert "xoxb-1" not in str(out)

    def test_url_is_truncated_to_its_origin(self):
        """A Slack webhook URL is itself the credential — the path is the secret."""
        out = _redact(
            _Channel("slack", {"webhook_url": "https://hooks.slack.com/services/T000/B000/XXXXsecret"})
        )
        shown = out["config"]["webhook_url"]
        assert "XXXXsecret" not in shown
        assert shown.startswith("https://hooks.slack.com")

    def test_email_target_is_left_readable(self):
        """An address is not a credential, and the operator needs to see which
        one is configured."""
        out = _redact(_Channel("email", {"email": "soc@example.com"}))
        assert out["config"]["email"] == "soc@example.com"


class TestUndeliverableChannelsAreRefusedOnWrite:
    """The dispatcher logs a warning and moves on. Catching it here means the
    operator learns at configuration time instead of never."""

    @pytest.mark.asyncio
    async def test_email_without_address_is_rejected(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await _validate_config("email", {})
        assert exc.value.status_code == 422

    @pytest.mark.asyncio
    async def test_webhook_without_url_is_rejected(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await _validate_config("webhook", {"secret": "x"})
        assert exc.value.status_code == 422
        assert "config.url" in exc.value.detail

    @pytest.mark.asyncio
    async def test_slack_without_webhook_url_is_rejected(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await _validate_config("slack", {})
        assert "config.webhook_url" in exc.value.detail

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://127.0.0.1:8000/api/v1/health",  # loopback
            "http://10.0.0.5/hook",  # RFC 1918
        ],
    )
    async def test_internal_destinations_are_blocked(self, url: str):
        """A webhook is an unattended outbound POST carrying incident detail,
        fired every 15 minutes. Pointing one at the metadata service or back at
        the platform itself must fail when it is created, not quietly forever."""
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await _validate_config("webhook", {"url": url})
        assert exc.value.status_code == 422
        assert "Blocked destination" in exc.value.detail


class TestContractWithTheDispatcher:
    def test_target_keys_match_what_the_dispatcher_reads(self):
        """incident_tasks reads cfg["email"], cfg["url"] and cfg["webhook_url"].
        If this mapping drifts, channels save cleanly and then never deliver —
        the silent-degradation shape this module exists to remove."""
        assert TARGET_KEY_BY_TYPE == {
            "email": "email",
            "webhook": "url",
            "slack": "webhook_url",
        }

    def test_channel_types_match_the_dispatcher_branches(self):
        import inspect

        from app.tasks import incident_tasks

        source = inspect.getsource(incident_tasks._dispatch_to_channels)
        for channel_type in CHANNEL_TYPES:
            assert f'"{channel_type}"' in source, (
                f"{channel_type!r} is offered by the API but _dispatch_to_channels "
                f"has no branch for it — channels of this type would save and "
                f"never deliver"
            )
