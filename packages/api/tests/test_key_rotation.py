# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
# NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"""Rotating DATA_ENCRYPTION_KEY must not silently destroy what it protects.

That key encrypts every TOTP seed, every notification-channel credential and the
leaked-secret evidence on findings. Before this, rotation was undocumented — the
guide covered three other secrets, one of which the project had already removed —
there was no re-encryption tooling, and both decrypt paths returned the
ciphertext on failure "for legacy cleartext support".

So the operator who rotated the key, which the guide's own Production
Recommendations advise doing, got no error anywhere. The symptom was every
MFA-enrolled user discovering that their codes no longer matched, with nothing in
the response or the logs naming the cause. The most likely moment to rotate a key
is after a suspected compromise, which is the worst moment to lock out every user
with second-factor authentication enabled.

Two changes, tested here: a decryption failure is now loud and specific, and a
previous key can be kept readable for the duration of the rotation so the
re-encryption sweep has something to read.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def crypto(monkeypatch):
    """app.utils.crypto with settings patched per test."""
    from app import config as config_module

    module = importlib.import_module("app.utils.crypto")
    return module, config_module.settings


CURRENT = "current-key-" + "c" * 32
PREVIOUS = "previous-key-" + "p" * 32


class TestADecryptionFailureIsLoud:
    def test_an_unopenable_value_raises_rather_than_returning_ciphertext(
        self, crypto, monkeypatch
    ):
        """The defect in one assertion. This used to return the ciphertext, so a
        rotated key produced a garbage TOTP secret instead of an error."""
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", PREVIOUS)
        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        blob = module.encrypt_totp_secret("JBSWY3DPEHPK3PXP")

        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        with pytest.raises(module.EncryptionKeyMismatch):
            module.decrypt_totp_secret(blob)

    def test_the_error_names_the_remedy(self, crypto, monkeypatch):
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", PREVIOUS)
        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        blob = module.encrypt_totp_secret("JBSWY3DPEHPK3PXP")

        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        with pytest.raises(module.EncryptionKeyMismatch, match="DATA_ENCRYPTION_KEY_PREVIOUS"):
            module.decrypt_totp_secret(blob)

    def test_genuine_cleartext_still_passes_through(self, crypto, monkeypatch):
        """Legacy rows written before field encryption existed must keep working:
        they are not base64 ciphertext and must not raise."""
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        assert module.decrypt_totp_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"

    def test_none_and_empty_are_unchanged(self, crypto, monkeypatch):
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        assert module.decrypt_totp_secret(None) is None
        assert module.decrypt_totp_secret("") is None


class TestTheRotationOverlap:
    def test_a_value_written_under_the_old_key_is_still_readable(
        self, crypto, monkeypatch
    ):
        """The whole point of the overlap: the sweep must be able to read what it
        is about to rewrite."""
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", PREVIOUS)
        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        blob = module.encrypt_totp_secret("JBSWY3DPEHPK3PXP")

        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        monkeypatch.setattr(settings, "data_encryption_key_previous", PREVIOUS)
        assert module.decrypt_totp_secret(blob) == "JBSWY3DPEHPK3PXP"

    def test_new_writes_use_the_current_key_only(self, crypto, monkeypatch):
        """Once the overlap is removed, values written during it must still open
        — otherwise the rotation would need a second rotation to finish."""
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        monkeypatch.setattr(settings, "data_encryption_key_previous", PREVIOUS)
        blob = module.encrypt_totp_secret("KRSXG5CTMVRXEZLU")

        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        assert module.decrypt_totp_secret(blob) == "KRSXG5CTMVRXEZLU"

    def test_the_current_key_is_tried_first(self, crypto, monkeypatch):
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        monkeypatch.setattr(settings, "data_encryption_key_previous", PREVIOUS)
        keys = module._candidate_keys()
        assert keys[0] == module.get_totp_encryption_key()
        assert len(keys) == 2

    def test_no_previous_key_means_one_candidate(self, crypto, monkeypatch):
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        assert len(module._candidate_keys()) == 1

    def test_json_columns_share_the_overlap(self, crypto, monkeypatch):
        """Notification credentials and leaked-secret evidence rotate too."""
        module, settings = crypto
        monkeypatch.setattr(settings, "data_encryption_key", PREVIOUS)
        monkeypatch.setattr(settings, "data_encryption_key_previous", "")
        blob = module.encrypt_json({"webhook_secret": "s3cr3t"})

        monkeypatch.setattr(settings, "data_encryption_key", CURRENT)
        monkeypatch.setattr(settings, "data_encryption_key_previous", PREVIOUS)
        assert module.decrypt_json(blob) == {"webhook_secret": "s3cr3t"}


class TestTheToolingAndTheGuideExist:
    def test_a_reencryption_script_exists(self):
        from pathlib import Path

        script = Path(__file__).resolve().parents[3] / "scripts" / "reencrypt.py"
        assert script.exists(), "rotation without a re-encryption sweep loses data"
        body = script.read_text()
        assert "--dry-run" in body

    def test_the_guide_documents_the_key_that_matters(self):
        from pathlib import Path

        guide = (
            Path(__file__).resolve().parents[3]
            / "docs" / "guide" / "secrets-rotation.md"
        ).read_text()
        assert "DATA_ENCRYPTION_KEY Rotation" in guide
        assert "DATA_ENCRYPTION_KEY_PREVIOUS" in guide

    def test_the_guide_no_longer_documents_a_removed_variable(self):
        """It carried a NEXTAUTH_SECRET procedure for a variable the project had
        already deleted, while omitting the one that can lose data."""
        from pathlib import Path

        guide = (
            Path(__file__).resolve().parents[3]
            / "docs" / "guide" / "secrets-rotation.md"
        ).read_text()
        assert "### NEXTAUTH_SECRET Rotation" not in guide
