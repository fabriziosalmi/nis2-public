# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""L14: field-level encryption of sensitive JSONB columns. Pure logic — the
crypto round-trip + the EncryptedJSON TypeDecorator (no DB engine needed)."""
from app.utils.crypto import decrypt_json, encrypt_json
from app.utils.encrypted_types import EncryptedJSON


def test_encrypt_json_round_trip():
    for value in (
        [{"type": "aws_key", "match": "AKIAIOSFODNN7EXAMPLE"}],
        {"webhook_url": "https://hooks.slack.com/x", "secret": "s3cr3t-token"},
        [],
        {},
    ):
        blob = encrypt_json(value)
        assert isinstance(blob, str)
        # ciphertext must not leak the plaintext secrets
        assert "AKIAIOSFODNN7EXAMPLE" not in blob
        assert "s3cr3t-token" not in blob
        assert decrypt_json(blob) == value


def test_typedecorator_wraps_and_unwraps():
    t = EncryptedJSON()
    original = {"webhook_url": "https://hooks.slack.com/x", "secret": "abc123"}
    stored = t.process_bind_param(original, None)
    assert set(stored.keys()) == {"__enc__"}
    assert "abc123" not in stored["__enc__"]
    assert t.process_result_value(stored, None) == original


def test_typedecorator_legacy_plaintext_passthrough():
    t = EncryptedJSON()
    # pre-encryption rows: a plain list or a dict without the wrapper key
    assert t.process_result_value([{"type": "x"}], None) == [{"type": "x"}]
    assert t.process_result_value({"url": "https://x"}, None) == {"url": "https://x"}


def test_typedecorator_none_passthrough():
    t = EncryptedJSON()
    assert t.process_bind_param(None, None) is None
    assert t.process_result_value(None, None) is None


def test_typedecorator_decrypt_failure_returns_raw():
    t = EncryptedJSON()
    bad = {"__enc__": "not-valid-base64-or-ciphertext!!!"}
    # Wrong/rotated key or tampering must not crash the read.
    assert t.process_result_value(bad, None) == bad
