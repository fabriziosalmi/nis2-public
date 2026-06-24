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


class Settings(BaseSettings):
    environment: str = "production"
    database_url: str = "postgresql+asyncpg://nis2:nis2secret@localhost:5432/nis2"
    database_url_sync: str = "postgresql://nis2:nis2secret@localhost:5432/nis2"
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

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @model_validator(mode="after")
    def _validate_runtime_config(self) -> "Settings":
        # RS256: auto-select algorithm when a private key is provided
        if self.jwt_private_key:
            self.jwt_algorithm = "RS256"

        if self.environment != "production":
            # Dev convenience: generate an ephemeral secret so `make dev` boots
            # cleanly. Tokens won't survive a restart — that's intentional, so
            # local sessions don't leak into production by accident.
            if self.jwt_secret in _INSECURE_JWT_DEFAULTS or len(self.jwt_secret) < 32:
                self.jwt_secret = secrets.token_urlsafe(32)
                logger.warning(
                    "[dev] JWT_SECRET missing or weak; using an ephemeral random "
                    "secret. Tokens will not survive restart. Set JWT_SECRET in "
                    ".env to persist sessions."
                )
            return self

        # RS256 in production: require public key too
        if self.jwt_algorithm == "RS256" and not self.jwt_private_key:
            raise RuntimeError(
                "Refusing to start: JWT_ALGORITHM is RS256 but JWT_PRIVATE_KEY is not set."
            )

        problems: list[str] = []
        if self.jwt_algorithm != "RS256" and self.jwt_secret in _INSECURE_JWT_DEFAULTS:
            problems.append(
                "JWT_SECRET is unset or uses an insecure placeholder. "
                "Generate one with `openssl rand -base64 32`."
            )
        elif self.jwt_algorithm != "RS256" and len(self.jwt_secret) < 32:
            problems.append("JWT_SECRET must be at least 32 characters in production.")
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
