# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Mount gate for GET /api/v1/auth/debug/last-email.

That endpoint returns the last outbound email — password-reset link included —
to any unauthenticated caller. It cannot be gated on a session, because the
whole point of the reset flow is that the caller has no session. Whether it is
mounted at all is therefore the entire security control, and until now nothing
tested it.

The chain it opens when wrongly mounted, with no credentials at all:

    POST /api/v1/auth/forgot-password   (public, CSRF-exempt, always 204)
    GET  /api/v1/auth/debug/last-email  -> reset token in the body
    POST /api/v1/auth/reset-password    -> account taken over

Historically the mount required one condition, ``environment != "production"``,
and .env.example shipped ``ENVIRONMENT=development`` while the README told
operators to copy it and run ``make prod``. One variable stood between a
documented deployment and full takeover of every account on it.

It now requires two independent conditions, and production refuses to boot if
the second one is set. These tests pin both halves.
"""

from __future__ import annotations

import importlib

import pytest
from pydantic import ValidationError

import app.config as config_module
from app.config import Settings


def _settings(**overrides):
    """Build a Settings instance without inheriting the developer's real .env.

    `_env_file=None` stops pydantic-settings reading the repo .env, so these
    assertions describe the code's behaviour rather than the current machine's.
    Every field the production validator requires is supplied explicitly.
    """
    base = dict(
        environment="production",
        jwt_secret="Yb2Q8vT1nR7wLm4Kd6Xs9Fj3Hc5Zp0Ag",  # 32 chars, no marker
        cors_origins="https://nis2.example.com",
        _env_file=None,
    )
    base.update(overrides)
    return Settings(**base)


class TestProductionRefusesTheFlag:
    def test_production_boot_fails_when_flag_is_set(self):
        """The flag is never legitimate in production: fail closed, loudly."""
        with pytest.raises((RuntimeError, ValidationError)) as exc:
            _settings(enable_dev_email_debug=True)
        assert "ENABLE_DEV_EMAIL_DEBUG" in str(exc.value)

    def test_production_boots_normally_without_the_flag(self):
        s = _settings()
        assert s.enable_dev_email_debug is False
        assert s.environment == "production"

    def test_flag_is_off_by_default_even_in_development(self):
        """Defaulting off in dev too is what makes the two conditions
        independent. If it defaulted on, `environment` would once again be the
        only thing standing in the way."""
        s = _settings(environment="development")
        assert s.enable_dev_email_debug is False


class TestMountGate:
    """The router-level condition, exercised by reimporting the module.

    The endpoint is registered at import time under an `if`, so the gate can
    only be observed by importing the module under each configuration.
    """

    @staticmethod
    def _debug_route_is_mounted(monkeypatch, *, environment: str, flag: bool) -> bool:
        monkeypatch.setattr(config_module.settings, "environment", environment)
        monkeypatch.setattr(config_module.settings, "enable_dev_email_debug", flag)
        auth = importlib.reload(importlib.import_module("app.routers.auth"))
        try:
            return any(
                getattr(r, "path", None) == "/auth/debug/last-email"
                for r in auth.router.routes
            )
        finally:
            # Leave the module in its default (unmounted) shape for other tests.
            monkeypatch.setattr(config_module.settings, "environment", environment)

    def test_not_mounted_in_production(self, monkeypatch):
        assert not self._debug_route_is_mounted(
            monkeypatch, environment="production", flag=False
        )

    def test_not_mounted_in_production_even_with_flag(self, monkeypatch):
        """Belt and braces. Settings already refuses this combination at boot,
        but the router must not depend on that having run."""
        assert not self._debug_route_is_mounted(
            monkeypatch, environment="production", flag=True
        )

    def test_not_mounted_in_development_without_the_flag(self, monkeypatch):
        """The regression that mattered: `make prod` with a stale
        ENVIRONMENT=development must no longer expose the endpoint."""
        assert not self._debug_route_is_mounted(
            monkeypatch, environment="development", flag=False
        )

    def test_mounted_only_in_development_with_the_flag(self, monkeypatch):
        """The one combination that should work — what the e2e suite and the
        dev compose stack rely on."""
        assert self._debug_route_is_mounted(
            monkeypatch, environment="development", flag=True
        )


def teardown_module(module):
    """Restore app.routers.auth to the ambient configuration.

    The mount gate is evaluated at import time, so the reloads above leave the
    module reflecting whichever config was tested last. Reload once more under
    the real settings so later tests in the same session import a coherent
    router.
    """
    importlib.reload(importlib.import_module("app.routers.auth"))
