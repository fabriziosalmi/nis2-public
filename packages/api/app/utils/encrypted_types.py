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

from app.utils.crypto import decrypt_json, encrypt_json

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
            except Exception:  # noqa: BLE001
                # Wrong/rotated key or tampering — don't crash the read; surface
                # the opaque wrapper and log. (A key rotation needs a re-encrypt
                # migration; this keeps the API up meanwhile.)
                logger.warning("EncryptedJSON: decryption failed; returning raw value")
                return value
        return value
