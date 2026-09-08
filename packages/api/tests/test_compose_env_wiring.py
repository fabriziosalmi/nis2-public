# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Compose interpolation must read the same .env the services do.

Docker Compose has two unrelated ways of getting values out of a .env file, and
this stack used both against *different* files without noticing:

  * ``${VAR}`` INTERPOLATION resolves from the .env in the PROJECT DIRECTORY,
    which defaults to the directory holding the compose file. Here that is
    ``infra/docker/``, where no .env exists.
  * ``env_file:`` on a service is an explicit relative path (``../../.env``) and
    does find the repo-root file.

Result: services with ``env_file:`` (api, celery-worker, celery-beat) received
the operator's real credentials, while every ``${VAR:-default}`` in the compose
files — POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB, REDIS_PASSWORD,
NEXT_PUBLIC_API_URL — silently fell back to its literal default. The two halves
of the stack agree only while .env still contains those same defaults. Set a
real POSTGRES_PASSWORD and postgres keeps ``nis2secret`` while the API connects
with the new value.

Observed directly during verification: the full dev stack up, postgres reporting
healthy, and every request failing with
``password authentication failed for user "nis2"``.

In production it was worse rather than subtler, because those guards are
``${POSTGRES_PASSWORD:?...}`` instead of ``:-default``. With no interpolation
source the guard fires and compose rejects the file, so `make prod` — the
install path the README documents — could not bring the stack up at all.

Nothing caught it because no CI job builds or boots the images. Until that job
exists, these cheap static checks stand in for it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MAKEFILE = REPO_ROOT / "Makefile"
COMPOSE_DIR = REPO_ROOT / "infra/docker"

COMPOSE_FILES = ["docker-compose.dev.yml", "docker-compose.prod.yml"]


def _compose_invocations() -> list[str]:
    """Every `docker compose` command line in the Makefile."""
    text = MAKEFILE.read_text(encoding="utf-8")
    return [
        line.strip()
        for line in text.splitlines()
        if "docker compose" in line and not line.lstrip().startswith("#")
    ]


def test_makefile_has_compose_invocations():
    """Sanity: the assertions below are meaningless if the grep finds nothing."""
    assert _compose_invocations(), "no `docker compose` lines found in the Makefile"


@pytest.mark.parametrize("invocation", _compose_invocations())
def test_every_compose_invocation_points_interpolation_at_repo_env(invocation: str):
    """`--env-file .env` (or an equivalent) on every call.

    Without it, ${VAR} interpolation reads infra/docker/.env — which does not
    exist — and every default in the compose files wins over the operator's
    real configuration.
    """
    assert "--env-file" in invocation or "--project-directory" in invocation, (
        f"compose invocation without --env-file:\n    {invocation}\n"
        f"Interpolation would resolve from infra/docker/.env (absent), so every "
        f"${{VAR:-default}} silently beats the operator's .env, and every "
        f"${{VAR:?...}} guard aborts the command."
    )


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_interpolated_variables_are_documented_in_env_example(compose_file: str):
    """Anything the compose files interpolate must exist in .env.example.

    A variable interpolated but absent from the template is one an operator
    cannot know to set, so it resolves to its default forever — which is the
    silent half of the bug above.
    """
    raw = (COMPOSE_DIR / compose_file).read_text(encoding="utf-8")
    # Comments explain the mechanism and quote placeholders like ${VAR:?msg};
    # only real directives count.
    text = "\n".join(
        line for line in raw.splitlines() if not line.lstrip().startswith("#")
    )
    interpolated = {
        m.group(1)
        for m in re.finditer(r"\$\{([A-Z][A-Z0-9_]*)[:?}-]", text)
        # $$VAR is a shell escape evaluated inside the container, not compose
        # interpolation, so it is out of scope here.
        if not text[max(0, m.start() - 1) : m.start()].endswith("$")
    }
    env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    declared = {
        m.group(1) for m in re.finditer(r"(?m)^([A-Z][A-Z0-9_]*)=", env_example)
    }
    # Build-time stamps, not deployment configuration. The Makefile exports them
    # from `git rev-parse` and the VERSION file so the images carry an OCI
    # revision label; an operator neither sets them nor should, and putting them
    # in .env.example would invite someone to pin a commit by hand. The
    # Dockerfiles default both to "unknown", so an image built outside the
    # Makefile is labelled honestly rather than wrongly.
    build_stamps = {"GIT_COMMIT", "APP_VERSION"}
    missing = interpolated - declared - build_stamps
    assert not missing, (
        f"{compose_file} interpolates {sorted(missing)}, which .env.example does "
        f"not declare. An operator has no way to know to set them, so they "
        f"resolve to their compose defaults permanently."
    )


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_postgres_healthcheck_is_not_hardcoded_to_a_user(compose_file: str):
    """`pg_isready -U nis2` ignored a customised POSTGRES_USER.

    The healthcheck then failed forever, and in prod Caddy gates on
    `service_healthy`, so the stack never finished coming up.
    """
    import yaml

    spec = yaml.safe_load((COMPOSE_DIR / compose_file).read_text())
    test = " ".join(spec["services"]["postgres"]["healthcheck"]["test"])
    assert "-U nis2" not in test, (
        f"{compose_file}: postgres healthcheck hardcodes the user; it must "
        f"follow POSTGRES_USER"
    )
    assert "POSTGRES_USER" in test


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_api_healthcheck_uses_readiness_not_liveness(compose_file: str):
    """Gating dependents on /health is gating on a probe that cannot fail.

    app/routers/health.py documents /health as liveness that "never returns a
    non-200". Both compose files used it for the container healthcheck, so
    `docker compose up --wait` reported success and Caddy began routing while
    the API could not reach its database. /health/ready is the probe with the
    correct semantics.
    """
    import yaml

    spec = yaml.safe_load((COMPOSE_DIR / compose_file).read_text())
    test = " ".join(spec["services"]["api"]["healthcheck"]["test"])
    assert "/api/v1/health/ready" in test, (
        f"{compose_file}: the api healthcheck must target /health/ready. "
        f"/health is a liveness probe that returns 200 unconditionally, so "
        f"anything gated on it is gated on nothing."
    )


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_postgres_provisions_the_least_privilege_role(compose_file: str):
    """Both stacks must create nis2_app, or DATABASE_URL cannot authenticate.

    .env.example points DATABASE_URL at nis2_app, so a stack that does not mount
    infra/docker/initdb comes up with an API that cannot log in to its own
    database — which is what happened to the dev stack when only prod was wired.
    """
    import yaml

    spec = yaml.safe_load((COMPOSE_DIR / compose_file).read_text())
    pg = spec["services"]["postgres"]
    volumes = [str(v) for v in pg.get("volumes", [])]
    assert any("docker-entrypoint-initdb.d" in v for v in volumes), (
        f"{compose_file}: postgres does not mount infra/docker/initdb, so "
        f"nis2_app is never created"
    )
    assert "NIS2_APP_PASSWORD" in (pg.get("environment") or {}), (
        f"{compose_file}: postgres has no NIS2_APP_PASSWORD, so the initdb "
        f"wrapper aborts"
    )
