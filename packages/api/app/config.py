# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import logging
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


_INSECURE_JWT_DEFAULTS = {
    "",
    "change-me",
    "GENERATE_ME_openssl_rand_base64_32",
    "secret",
    "changeme",
}

# Exact-match on a literal is the wrong shape for this check, and it failed
# exactly the way that shape always fails. v2.5.5 renamed the .env.example
# placeholders from `GENERATE_ME_openssl_rand_base64_32` to
# `CHANGE_ME_RUN_openssl_rand_base64_32`; the set above kept the OLD string, so
# from that release on, the shipped placeholder was:
#   - not in _INSECURE_JWT_DEFAULTS  (renamed, exact match missed it),
#   - 36 characters long             (so the >= 32 length floor passed it),
#   - not matched by the Makefile's `^JWT_SECRET=GENERATE_ME` grep either.
# Net effect: `cp .env.example .env && make prod` booted production signing
# every JWT with a key published in this repository. Anyone could mint a token
# for any user in any organisation.
#
# Substring markers instead of literals: every realistic unedited template value
# contains at least one, while a real secret does not. Renaming a placeholder can
# no longer silently disarm the check — which is the property the exact-match set
# never had.
#
# Marker selection is deliberately conservative, because a detector that rejects
# a VALID secret is worse than one that misses an exotic template: it teaches the
# operator to work around the check. Every marker below is either
#   (a) long enough that a chance collision is not credible ("placeholder"), or
#   (b) anchored on "_" or "-", neither of which appears in base64 output
#       ([A-Za-z0-9+/=]), so it cannot collide with `openssl rand -base64 32`.
# Short all-alphanumeric markers were tried and removed: "xxxx" rejected the
# legitimate 40-char secret in tests/test_data_encryption_key.py, and "todo"
# carries a ~1-in-25k false-positive rate against random base64 for negligible
# benefit. test_real_generated_secrets_are_not_flagged guards this boundary.
_PLACEHOLDER_MARKERS = (
    "change_me",
    "change-me",
    "changeme",
    "generate_me",
    "generate-me",
    "generateme",
    "placeholder",
    "yourdomain",
    "your_",
    "insert_",
    "replace_",
)


def looks_like_placeholder(value: str) -> bool:
    """True when `value` is recognisably an unedited template value.

    Used for every secret the platform refuses to boot on. Deliberately
    marker-based rather than an allow/deny list of literals — see the comment
    on _PLACEHOLDER_MARKERS for why the literal version failed.
    """
    if value in _INSECURE_JWT_DEFAULTS:
        return True
    low = value.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


class Settings(BaseSettings):
    environment: str = "production"
    database_url: str = "postgresql+asyncpg://nis2:nis2secret@localhost:5432/nis2"
    database_url_sync: str = "postgresql://nis2:nis2secret@localhost:5432/nis2"

    # Tenant isolation rests on Postgres RLS, and RLS is BYPASSED for SUPERUSER
    # / BYPASSRLS roles — FORCE ROW LEVEL SECURITY does not bind them either.
    # So the runtime identity above must be a plain NOSUPERUSER NOBYPASSRLS role
    # (infra/docker/initdb provisions `nis2_app`).
    #
    # That role deliberately has DML only, which leaves nobody able to build the
    # schema: `alembic upgrade head` in entrypoint.sh, ensure_schema()'s
    # create_all, and setup_row_level_security()'s ALTER/CREATE POLICY/CREATE
    # FUNCTION/GRANT/REVOKE all need DDL. The platform therefore needs TWO
    # identities, and until now it modelled only one — which is why the
    # least-privilege role was documented in infra/docker/initdb but never
    # actually reachable: pointing DATABASE_URL at it broke schema creation.
    #
    # These carry the privileged identity used ONLY for migrations and the
    # boot-time bootstrap. Empty means "same as database_url", which preserves
    # the historical single-identity behaviour for existing deployments.
    migration_database_url: str = ""
    migration_database_url_sync: str = ""
    # SQLAlchemy pool, PER GUNICORN WORKER. The total demand on Postgres is
    # workers x (db_pool_size + db_max_overflow), plus the Celery worker and
    # beat. Keep that product below the server's max_connections (100 in the
    # stock postgres image): the previous 20 + 10 with four workers asked for
    # 120 and Postgres refuses the excess outright.
    db_pool_size: int = 10
    db_max_overflow: int = 5

    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"

    # RS256 support. When jwt_private_key is set, the platform uses RS256
    # instead of HS256. jwt_algorithm is overridden automatically.
    # Generate with: openssl genrsa -out private.pem 2048
    #                openssl rsa -in private.pem -pubout -out public.pem
    # Set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY env vars to the PEM content
    # (with literal \n or as multi-line).
    jwt_private_key: str = ""  # PEM-encoded RSA private key (RS256 signing)
    jwt_public_key: str = ""  # PEM-encoded RSA public key (RS256 verification)

    # Dedicated key for field-level encryption (TOTP/MFA secrets today; other
    # encrypted columns later). Independent of jwt_secret. When unset, the TOTP
    # key derives from jwt_secret for backward compatibility with deployments
    # provisioned before this key existed (fine for HS256). RS256 mode has no
    # jwt_secret, so production REQUIRES this — see _validate_runtime_config.
    data_encryption_key: str = ""
    # The key this deployment is rotating AWAY from. Set it to the old value for
    # the duration of a rotation: decryption tries the current key first and
    # falls back to this one, so existing MFA seeds and notification credentials
    # keep working while `make reencrypt` rewrites them under the new key. Unset
    # it once that has finished.
    #
    # Without an overlap, rotating DATA_ENCRYPTION_KEY was not merely unsupported
    # but silently destructive: every TOTP seed and every stored credential
    # became undecryptable, and the decrypt paths returned the ciphertext instead
    # of raising, so the symptom was every MFA user being unable to log in with
    # nothing in the response explaining why.
    data_encryption_key_previous: str = ""

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    cors_origins: str = ""

    # Password-reset (B05). The link emailed to users points at
    # ${public_url}/reset-password?token=<raw>. In production the
    # operator sets public_url to the customer domain; in dev we fall
    # back to the local web port so `make dev` works without extra
    # env vars.
    public_url: str = "http://localhost:8077"
    reset_token_ttl_minutes: int = 30

    # SMTP (optional). When smtp_host is empty the email utility
    # logs the message body and stores it in an in-memory queue
    # instead of dialling an MTA — that's how `make dev` and the e2e
    # suite avoid needing a real mailserver. Production deploys must
    # set host/port/from at minimum.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@nis2.local"
    smtp_starttls: bool = True
    smtp_ssl: bool = False  # Mutually exclusive with starttls (port 465 typical)

    # v2.4.20 (audit reports-005): report files written under
    # /tmp/nis2-reports stay there forever absent a sweeper. With
    # 100s of scans/day in production, /tmp fills up and the worker
    # eventually OOMs the disk. The Celery beat schedule includes
    # `cleanup-old-reports` running once daily; this knob is the
    # cutoff age. Default 30 days — long enough for a compliance
    # team to download last week's report after a holiday, short
    # enough that the disk doesn't grow unbounded.
    report_ttl_days: int = 30

    # GDPR Art. 5(1)(e) storage limitation for audit logs.
    # The privacy notice (docs/privacy.md §7.2) advertises 90 days as the
    # default. Set AUDIT_LOG_RETENTION_DAYS in .env to match your own
    # jurisdiction's audit-trail obligation (NIS2 Art. 21 recommends ≥ 12
    # months for incident evidence; raise this on instances that handle
    # security incidents). The cleanup_tasks beat job prunes rows daily.
    audit_log_retention_days: int = 90

    # Maximum number of report-generation Celery tasks that a single
    # organisation may have running concurrently. Each task consumes one
    # Celery worker slot and can be CPU/disk intensive (a 50k-finding
    # scan takes ~30 s). The 5/min/IP rate limit on POST /reports/generate
    # already caps the burst rate; this cap prevents a single org from
    # monopolising the entire worker pool across multiple scans and formats.
    # Raise on instances with many workers and trusted users; lower on
    # shared / multi-tenant setups. Default 3.
    max_concurrent_reports_per_org: int = 3

    # AI remediation copilot (POST /remediation/explain). OpenAI egress is OFF by
    # default — OPENAI_API_KEY alone does NOT enable it; ENABLE_OPENAI must be true.
    # See docs/privacy.md §7.3 (transborder data flow to OpenAI, USA).
    enable_openai: bool = False

    # Mounts GET /api/v1/auth/debug/last-email, which returns the full body of
    # the most recent outbound email — including the password-reset link — to
    # ANY caller, with no authentication, no role check and no rate limit.
    #
    # It exists because the e2e suite drives the real reset flow end to end
    # (tests/test_e2e_live.py::TestForgotPassword), which is worth keeping: that
    # flow is security-critical and deserves live coverage. What is not worth
    # keeping is the old mount condition — `environment != "production"` alone.
    # A single mis-set variable then exposed a complete unauthenticated account
    # takeover: POST /auth/forgot-password for any address (public, CSRF-exempt,
    # always 204) -> GET here to read the token -> POST /auth/reset-password.
    #
    # So the endpoint now needs TWO independent conditions: a non-production
    # environment AND this flag, which defaults off even in development and
    # which no real deployment has any reason to set. _validate_runtime_config
    # additionally REFUSES TO BOOT if it is on in production, so turning it on
    # by accident fails loudly instead of silently opening the hole.
    enable_dev_email_debug: bool = False

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def effective_migration_url(self) -> str:
        """Async URL for DDL: migrations, create_all, RLS/policy bootstrap."""
        return self.migration_database_url or self.database_url

    @property
    def effective_migration_url_sync(self) -> str:
        """Sync variant of effective_migration_url (Alembic offline mode)."""
        return self.migration_database_url_sync or self.database_url_sync

    @property
    def uses_split_db_identities(self) -> bool:
        """True when a distinct privileged identity is configured.

        False means runtime and migrations share one role — the historical
        behaviour, and the shape in which RLS is decorative if that role happens
        to be a superuser.
        """
        return bool(self.migration_database_url or self.migration_database_url_sync)

    @model_validator(mode="after")
    def _validate_runtime_config(self) -> "Settings":
        # RS256: auto-select algorithm when a private key is provided
        if self.jwt_private_key:
            self.jwt_algorithm = "RS256"

        if self.environment != "production":
            # Dev convenience: generate an ephemeral secret so `make dev` boots
            # cleanly. Tokens won't survive a restart — that's intentional, so
            # local sessions don't leak into production by accident.
            if looks_like_placeholder(self.jwt_secret) or len(self.jwt_secret) < 32:
                self.jwt_secret = secrets.token_urlsafe(32)
                logger.warning(
                    "[dev] JWT_SECRET missing or weak; using an ephemeral random "
                    "secret. Tokens will not survive restart. Set JWT_SECRET in "
                    ".env to persist sessions."
                )
            return self

        # Fail closed rather than fail quiet: this flag mounts an
        # unauthenticated endpoint that hands out password-reset links. In
        # production it is never a legitimate setting, so refuse the boot
        # instead of logging a warning nobody reads.
        if self.enable_dev_email_debug:
            raise RuntimeError(
                "Refusing to start: ENABLE_DEV_EMAIL_DEBUG is set in production. "
                "It mounts GET /api/v1/auth/debug/last-email, which returns the "
                "last outbound email — including password-reset links — to any "
                "unauthenticated caller. Unset it."
            )

        # RS256 in production: require public key too
        if self.jwt_algorithm == "RS256" and not self.jwt_private_key:
            raise RuntimeError(
                "Refusing to start: JWT_ALGORITHM is RS256 but JWT_PRIVATE_KEY is not set."
            )

        problems: list[str] = []
        if self.jwt_algorithm != "RS256" and looks_like_placeholder(self.jwt_secret):
            problems.append(
                "JWT_SECRET is unset or uses an insecure placeholder. "
                "Generate one with `openssl rand -base64 32`."
            )
        elif self.jwt_algorithm != "RS256" and len(self.jwt_secret) < 32:
            problems.append("JWT_SECRET must be at least 32 characters in production.")

        # Field-level encryption key material (TOTP/MFA secrets).
        # get_totp_encryption_key() uses DATA_ENCRYPTION_KEY, falling back to
        # JWT_SECRET. Independent of the JWT algorithm: an RS256 deploy has no
        # JWT_SECRET, so without a dedicated key MFA encryption would silently
        # key off a hardcoded literal — defeating MFA for anyone with a DB dump.
        # Require strong material either way; fail closed.
        totp_key_material = self.data_encryption_key or self.jwt_secret
        if looks_like_placeholder(totp_key_material) or len(totp_key_material) < 32:
            problems.append(
                "DATA_ENCRYPTION_KEY must be a strong secret of at least 32 "
                "characters — it keys field-level MFA/TOTP encryption. In RS256 "
                "mode there is no JWT_SECRET to fall back on, so it is required. "
                "Generate with `openssl rand -base64 32`."
            )
        if not self.cors_origins.strip():
            problems.append(
                "CORS_ORIGINS must be set explicitly in production "
                "(comma-separated allow-list, no wildcards)."
            )
        if problems:
            raise RuntimeError(
                "Refusing to start: insecure configuration detected.\n  - "
                + "\n  - ".join(problems)
                + "\n\nSet ENVIRONMENT=development to relax these checks for local work."
            )
        return self


settings = Settings()
