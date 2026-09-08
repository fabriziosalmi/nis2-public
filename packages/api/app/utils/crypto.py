# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import base64
import hashlib
import json
import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import settings


class EncryptionKeyMismatch(RuntimeError):
    """Stored ciphertext that no configured key can open.

    Distinct from a tamper or a corrupt row so the operator can tell "I rotated
    the key and did not re-encrypt" from "this value is damaged".
    """



def get_totp_encryption_key() -> bytes:
    """Derive the 32-byte AES-GCM key for field-level TOTP encryption.

    Prefers the dedicated DATA_ENCRYPTION_KEY; falls back to JWT_SECRET so
    deployments provisioned before DATA_ENCRYPTION_KEY existed keep the same
    derived key and their stored secrets stay decryptable. Fails closed when
    neither is available — it must never derive from a hardcoded literal, which
    would let anyone with the (public, AGPL) source decrypt MFA seeds from a
    stolen DB. Production config validation guarantees key material is present.
    """
    secret = settings.data_encryption_key or settings.jwt_secret
    if not secret:
        raise RuntimeError(
            "No encryption key for TOTP secrets: set DATA_ENCRYPTION_KEY (or "
            "JWT_SECRET). Refusing to derive a key from a hardcoded value."
        )
    return hashlib.sha256(secret.encode()).digest()


def get_previous_encryption_key() -> Optional[bytes]:
    """The key being rotated away from, if a rotation is in progress.

    Returns None when DATA_ENCRYPTION_KEY_PREVIOUS is unset, which is the steady
    state. During a rotation the decrypt paths try the current key first and this
    one second, so a value written under the old key stays readable until the
    re-encryption sweep has rewritten it.
    """
    previous = settings.data_encryption_key_previous
    if not previous:
        return None
    return hashlib.sha256(previous.encode()).digest()


def _candidate_keys() -> list:
    """Keys to try when decrypting, current first."""
    keys = [get_totp_encryption_key()]
    previous = get_previous_encryption_key()
    if previous is not None:
        keys.append(previous)
    return keys


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
    except Exception:
        # Not base64 at all: a legacy cleartext row. Genuinely not encrypted.
        return encrypted_str

    if len(raw_data) < 28:  # Minimum length: 12 (nonce) + 16 (tag)
        return encrypted_str

    nonce, ciphertext_tag = raw_data[:12], raw_data[12:]
    for key in _candidate_keys():
        try:
            return AESGCM(key).decrypt(nonce, ciphertext_tag, None).decode("utf-8")
        except Exception:
            continue

    # Encrypted, and no configured key opens it. This used to return the
    # ciphertext under a "legacy cleartext support" comment, which meant a
    # rotated key produced a garbage TOTP secret rather than an error: every
    # enrolled user was locked out and the only signal was their codes silently
    # never matching. Raising names the cause, and the caller decides.
    raise EncryptionKeyMismatch(
        "A stored secret could not be decrypted with any configured key. If "
        "DATA_ENCRYPTION_KEY was rotated, set DATA_ENCRYPTION_KEY_PREVIOUS to "
        "the old value and run the re-encryption sweep."
    )


def encrypt_json(value) -> str:
    """AES-GCM-encrypt a JSON-serialisable value to a base64 string.

    Keyed by the same DATA_ENCRYPTION_KEY as TOTP secrets
    (get_totp_encryption_key). Used for field-level encryption of JSONB columns
    that hold sensitive data at rest (leaked-secret evidence, notification
    credentials). Format: base64(nonce[12] + ciphertext + tag[16]).
    """
    key = get_totp_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(nonce + aesgcm.encrypt(nonce, raw, None)).decode("utf-8")


def decrypt_json(blob: str):
    """Inverse of encrypt_json. Raises on tamper / wrong key (callers handle)."""
    raw = base64.b64decode(blob.encode("utf-8"), validate=True)
    nonce, ciphertext_tag = raw[:12], raw[12:]
    for key in _candidate_keys():
        try:
            return json.loads(
                AESGCM(key).decrypt(nonce, ciphertext_tag, None).decode("utf-8")
            )
        except Exception:
            continue
    raise EncryptionKeyMismatch(
        "An encrypted column could not be decrypted with any configured key. "
        "If DATA_ENCRYPTION_KEY was rotated, set DATA_ENCRYPTION_KEY_PREVIOUS "
        "to the old value and run the re-encryption sweep."
    )
