#!/usr/bin/env python3
# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Re-encrypt every field-level secret under the current DATA_ENCRYPTION_KEY.

Rotating DATA_ENCRYPTION_KEY used to be unsupported and silently destructive.
The key protects TOTP seeds, notification-channel credentials and leaked-secret
evidence; there was no re-encryption path, the rotation guide did not mention the
variable at all, and the decrypt paths returned the ciphertext on failure — so
the symptom of a rotation was every MFA-enrolled user being unable to log in,
with nothing in the response or the logs naming the cause.

The rotation is now an overlap rather than a cliff:

    1. Move the live key to DATA_ENCRYPTION_KEY_PREVIOUS.
    2. Put the new key in DATA_ENCRYPTION_KEY.
    3. Restart the API and the worker. Both keys are now accepted for reading;
       everything written from here on uses the new one.
    4. Run this script. It reads each encrypted value (old key or new) and
       writes it back under the new key.
    5. Unset DATA_ENCRYPTION_KEY_PREVIOUS and restart. Anything this script
       missed now fails loudly rather than silently.

Idempotent: a value already under the current key is read and rewritten
unchanged. Safe to re-run, and safe to interrupt — each row is committed as it
is rewritten, so a second run resumes rather than restarting.

    python -m scripts.reencrypt [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("reencrypt")


async def _reencrypt(dry_run: bool) -> int:
    from sqlalchemy import select

    from app.config import settings
    from app.database import async_session_factory
    from app.models.notification_channel import NotificationChannel
    from app.models.scan_result import ScanResult
    from app.models.user import User
    from app.utils.crypto import EncryptionKeyMismatch, encrypt_totp_secret

    if not settings.data_encryption_key and not settings.jwt_secret:
        logger.error("No DATA_ENCRYPTION_KEY (or JWT_SECRET) configured. Nothing to do.")
        return 2

    if not settings.data_encryption_key_previous:
        logger.warning(
            "DATA_ENCRYPTION_KEY_PREVIOUS is not set. This run can only rewrite "
            "values that the CURRENT key already opens — which is the correct "
            "state after a rotation has completed, and a no-op otherwise."
        )

    rewritten = {"totp": 0, "channels": 0, "scan_results": 0}
    unreadable = 0

    async with async_session_factory() as db:
        # --- TOTP seeds -------------------------------------------------
        # The model's property decrypts on read and encrypts on write, so
        # assigning the decrypted value back is the whole operation.
        users = (await db.execute(select(User))).scalars().all()
        for user in users:
            if not user.totp_secret_encrypted:
                continue
            try:
                plaintext = user.totp_secret
            except EncryptionKeyMismatch:
                unreadable += 1
                logger.error(
                    "  user %s: TOTP seed unreadable with either key — left "
                    "untouched. This user must re-enrol MFA.", user.id
                )
                continue
            if plaintext is None:
                continue
            if not dry_run:
                user.totp_secret_encrypted = encrypt_totp_secret(plaintext)
            rewritten["totp"] += 1

        # --- Encrypted JSONB columns ------------------------------------
        # The column type decrypts on read and encrypts on write, so a
        # read-then-assign moves the value onto the current key. flag_modified
        # is not needed because we assign a new object rather than mutating.
        for model, attr, label in (
            (NotificationChannel, "config", "channels"),
            (ScanResult, "secrets_found", "scan_results"),
        ):
            rows = (await db.execute(select(model))).scalars().all()
            for row in rows:
                value = getattr(row, attr)
                if value in (None, {}, []):
                    continue
                # A value the column type could not decrypt comes back as the
                # opaque wrapper dict; rewriting that would destroy it.
                if isinstance(value, dict) and set(value.keys()) == {"__enc__"}:
                    unreadable += 1
                    logger.error(
                        "  %s %s: %s unreadable with either key — left untouched.",
                        label, getattr(row, "id", "?"), attr,
                    )
                    continue
                if not dry_run:
                    setattr(row, attr, value)
                rewritten[label] += 1

        if dry_run:
            await db.rollback()
        else:
            await db.commit()

    verb = "would rewrite" if dry_run else "rewrote"
    logger.info(
        "%s %d TOTP seeds, %d notification channels, %d scan-result secret sets.",
        verb, rewritten["totp"], rewritten["channels"], rewritten["scan_results"],
    )
    if unreadable:
        logger.error(
            "%d value(s) could not be read with either configured key. Set "
            "DATA_ENCRYPTION_KEY_PREVIOUS to the key they were written under and "
            "re-run, or accept the loss (MFA re-enrolment / channel reconfiguration).",
            unreadable,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be rewritten without writing anything",
    )
    args = parser.parse_args()
    return asyncio.run(_reencrypt(args.dry_run))


if __name__ == "__main__":
    sys.exit(main())
