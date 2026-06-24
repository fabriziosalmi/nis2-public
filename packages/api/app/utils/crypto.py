# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import base64
import hashlib
import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import settings


def get_totp_encryption_key() -> bytes:
    """Derive a 32-byte key from settings.jwt_secret."""
    secret = settings.jwt_secret or "temporary-ephemeral-secret-key-for-mfa"
    return hashlib.sha256(secret.encode()).digest()


def encrypt_totp_secret(secret_str: Optional[str]) -> Optional[str]:
    """Encrypt a TOTP secret base32 string using AES-GCM.

    Format: base64(nonce [12 bytes] + ciphertext [variable] + tag [16 bytes])
    """
    if not secret_str:
        return None
    key = get_totp_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, secret_str.encode("utf-8"), None)
    return base64.b64encode(nonce + encrypted_data).decode("utf-8")


def decrypt_totp_secret(encrypted_str: Optional[str]) -> Optional[str]:
    """Decrypt an encrypted TOTP secret.

    If the string is not encrypted (e.g. legacy cleartext records) or if decryption
    fails, returns the original string as-is for backward compatibility.
    """
    if not encrypted_str:
        return None
    try:
        raw_data = base64.b64decode(encrypted_str.encode("utf-8"), validate=True)
        if len(raw_data) < 28:  # Minimum length: 12 (nonce) + 16 (tag)
            return encrypted_str
        nonce = raw_data[:12]
        ciphertext_tag = raw_data[12:]
        key = get_totp_encryption_key()
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext_tag, None)
        return decrypted_bytes.decode("utf-8")
    except Exception:
        # Decryption failed; return as-is (legacy cleartext support)
        return encrypted_str
