# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Regression guard: no value shipped in .env.example may boot production.

Why this file exists
--------------------
The platform had three independent placeholder detectors:

  1. ``_INSECURE_JWT_DEFAULTS`` in app/config.py (exact-match set),
  2. the ``^JWT_SECRET=GENERATE_ME`` grep in the Makefile's prod-preflight,
  3. the ``>= 32 chars`` length floor in app/config.py.

v2.5.5 renamed the .env.example placeholders from ``GENERATE_ME_*`` to
``CHANGE_ME_*``. That single rename disarmed (1) and (2) simultaneously, and
the new placeholder was 36 characters long so it sailed through (3) as well.
From that release until this test landed, ``cp .env.example .env && make prod``
produced a production deployment signing every JWT with a key published in this
repository — enough to mint a valid token for any user in any organisation.

Nothing caught it because nothing asserted the relationship between the
template file and the validators. That relationship is the invariant, so it is
what this file tests: whatever the placeholders are *called*, they must be
rejected. A future rename now fails here instead of shipping.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.config import _PLACEHOLDER_MARKERS, looks_like_placeholder

# packages/api/tests/ -> packages/api/ -> packages/ -> repo root
REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
MAKEFILE = REPO_ROOT / "Makefile"

# Keys whose value is credential material. An unedited value for any of these
# must never be accepted by a production boot.
SECRET_KEYS = {
    "POSTGRES_PASSWORD",
    "NIS2_APP_PASSWORD",
    "REDIS_PASSWORD",
    "JWT_SECRET",
    "NEXTAUTH_SECRET",
    "DATA_ENCRYPTION_KEY",
    "SMTP_PASSWORD",
    "OPENAI_API_KEY",
}

# Keys that are not secrets but whose shipped value is still a placeholder that
# must not reach production: DOMAIN drives Caddy's ACME certificate request.
PLACEHOLDER_KEYS = {"DOMAIN"}


def _parse_env_example() -> dict[str, str]:
    assert ENV_EXAMPLE.is_file(), f".env.example not found at {ENV_EXAMPLE}"
    values: dict[str, str] = {}
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Z0-9_]+)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


ENV_VALUES = _parse_env_example()


def test_env_example_is_parseable():
    """Sanity: the template exists and has the keys the rest of the file asserts on."""
    assert ENV_VALUES, ".env.example produced no key=value pairs"
    assert "JWT_SECRET" in ENV_VALUES
    assert "ENVIRONMENT" in ENV_VALUES


@pytest.mark.parametrize("key", sorted(SECRET_KEYS))
def test_shipped_secret_placeholder_is_rejected(key: str):
    """Every credential in .env.example must be recognised as a placeholder.

    An empty value is fine — it means "no default, operator must supply one",
    and the production validators already treat empty as missing. What must
    never happen is a *non-empty* shipped value that the validators accept:
    that is a published credential which silently becomes a live one.
    """
    if key not in ENV_VALUES:
        pytest.skip(f"{key} is not present in .env.example")
    value = ENV_VALUES[key]
    if value == "":
        return
    assert looks_like_placeholder(value), (
        f"{key}={value!r} is shipped in .env.example but is NOT recognised as a "
        f"placeholder by app.config.looks_like_placeholder(). A deployment that "
        f"copies the template unedited would run production on this value. "
        f"Either add a marker to _PLACEHOLDER_MARKERS or change the template."
    )


@pytest.mark.parametrize("key", sorted(PLACEHOLDER_KEYS))
def test_shipped_non_secret_placeholder_is_recognisable(key: str):
    """Non-credential placeholders must also be detectable by the same helper."""
    if key not in ENV_VALUES:
        pytest.skip(f"{key} is not present in .env.example")
    value = ENV_VALUES[key]
    if value == "":
        return
    assert looks_like_placeholder(value), (
        f"{key}={value!r} in .env.example is not detectable as a placeholder."
    )


def test_makefile_preflight_markers_match_config():
    """The Makefile's placeholder grep must use the same markers as config.py.

    There are two independent detectors — the shell grep in `prod-preflight`
    (which stops a bad deploy before the stack is even built) and
    looks_like_placeholder() (which stops the API booting). Two lists that must
    agree but are not mechanically linked is exactly the shape of the original
    bug: the config set and the Makefile grep drifted apart at v2.5.5 and both
    stopped matching the shipped placeholders.

    This asserts the Makefile's alternation is a superset of the Python markers,
    so the cheap early gate can never be laxer than the late one.
    """
    makefile = MAKEFILE.read_text(encoding="utf-8")
    alternations = re.findall(r"\((change_me\|[^)]*)\)", makefile)
    assert alternations, (
        "no placeholder alternation found in the Makefile — has prod-preflight's "
        "secret check been renamed or removed?"
    )
    for alternation in alternations:
        shell_markers = set(alternation.split("|"))
        missing = set(_PLACEHOLDER_MARKERS) - shell_markers
        assert not missing, (
            f"Makefile prod-preflight does not check for {sorted(missing)}, which "
            f"app.config._PLACEHOLDER_MARKERS does. The two detectors have "
            f"drifted — that drift is the bug this test exists to prevent."
        )


def test_env_example_defaults_to_production():
    """The template must fail safe, not fail convenient.

    Shipping ENVIRONMENT=development meant that following the README verbatim
    disabled the Secure cookie flag, mounted the unauthenticated
    /auth/debug/last-email helper, skipped the JWT/CORS boot validation, skipped
    the SUPERUSER/BYPASSRLS refusal, and diverted all outbound mail to an
    in-memory outbox.
    """
    assert ENV_VALUES.get("ENVIRONMENT") == "production", (
        ".env.example must ship ENVIRONMENT=production; it is the template for "
        "a real deployment."
    )


def test_real_generated_secrets_are_not_flagged():
    """The detector must not reject legitimate `openssl rand -base64 32` output.

    Guards against a future over-broad marker turning the check into a
    false-positive generator, which would push operators to work around it.
    """
    import base64
    import secrets as _secrets

    for _ in range(2000):
        candidate = base64.b64encode(_secrets.token_bytes(32)).decode()
        assert not looks_like_placeholder(candidate), (
            f"randomly generated secret {candidate!r} was wrongly flagged as a "
            f"placeholder — a marker in _PLACEHOLDER_MARKERS is too broad"
        )


@pytest.mark.parametrize(
    "value",
    [
        "x" * 40,  # the fixture in test_data_encryption_key.py
        "a" * 32,
        "0" * 64,
        "correct-horse-battery-staple-correct-horse",  # long passphrase with '-'
        "S3cr3t-Passphrase-With-Dashes-And-Length-42",
        "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgc2VjcmV0",  # plain base64
    ],
)
def test_legitimate_secret_shapes_are_not_flagged(value: str):
    """Non-random but entirely legitimate secret shapes must pass.

    The first case is not hypothetical: an earlier revision of this work added
    "xxxx" to _PLACEHOLDER_MARKERS, which rejected the 40-character ``"x" * 40``
    fixture that test_data_encryption_key.py uses to assert that a strong
    HS256 secret boots. Three tests went red. The marker was removed rather than
    the fixture weakened — a validator that rejects valid input is a worse
    failure than one that misses an exotic template.

    Repeated-character and dash-separated passphrases are the shapes most likely
    to collide with a careless marker, so they are pinned here explicitly.
    """
    assert not looks_like_placeholder(value), (
        f"{value!r} is a legitimate secret shape but was flagged as a "
        f"placeholder — a marker in _PLACEHOLDER_MARKERS is too broad"
    )
