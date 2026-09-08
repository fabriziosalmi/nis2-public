# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""SQLAlchemy column type that transparently encrypts JSON at rest (L14).

The value is stored as a JSONB wrapper ``{"__enc__": "<base64 AES-GCM>"}``, so
the column stays ``jsonb`` — no DDL migration is needed. Reads of legacy
(pre-encryption) plaintext rows pass through unchanged, so existing data keeps
working and is encrypted lazily as rows are rewritten. Keyed by
DATA_ENCRYPTION_KEY (see app.utils.crypto / config).
"""
from __future__ import annotations

import logging

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from app.utils.crypto import EncryptionKeyMismatch, decrypt_json, encrypt_json

logger = logging.getLogger(__name__)

_WRAP_KEY = "__enc__"


class EncryptedJSON(TypeDecorator):
    """JSONB column whose value is AES-GCM-encrypted at rest."""

    impl = JSONB
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return {_WRAP_KEY: encrypt_json(value)}

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        # Encrypted wrapper → decrypt. Anything else is legacy plaintext.
        if isinstance(value, dict) and set(value.keys()) == {_WRAP_KEY}:
            try:
                return decrypt_json(value[_WRAP_KEY])
            except EncryptionKeyMismatch:
                # No configured key opens this. Keep the API up — a single
                # unreadable notification credential must not take down every
                # request that touches the row — but say precisely what happened
                # and what to do, rather than the previous generic warning that
                # left an operator to guess between a rotated key, a restored
                # backup and a corrupt value.
                logger.error(
                    "EncryptedJSON: no configured key decrypts this value. If "
                    "DATA_ENCRYPTION_KEY was rotated, set "
                    "DATA_ENCRYPTION_KEY_PREVIOUS and run `make reencrypt`."
                )
                return value
            except Exception:  # noqa: BLE001
                # Malformed or tampered ciphertext, as distinct from a key
                # mismatch.
                logger.warning("EncryptedJSON: value is not decryptable; returning raw")
                return value
        return value
