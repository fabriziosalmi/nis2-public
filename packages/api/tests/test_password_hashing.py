# Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-only
"""L4: passwords must not be silently truncated at bcrypt's 72-byte limit, and
legacy bcrypt hashes must keep verifying + upgrade transparently. Pure passlib."""
import passlib.hash

from app.routers.auth import pwd_context


def test_new_hashes_use_bcrypt_sha256():
    h = pwd_context.hash("correct horse battery staple")
    assert pwd_context.identify(h) == "bcrypt_sha256"


def test_long_passphrase_not_truncated_at_72_bytes():
    # Two passphrases identical for the first 72 bytes, differing only after.
    base = "a" * 72
    p1, p2 = base + "ONE", base + "TWO"
    h1 = pwd_context.hash(p1)
    assert pwd_context.verify(p1, h1)
    # Under plain bcrypt this would WRONGLY be True (both truncate to `base`).
    assert not pwd_context.verify(p2, h1)


def test_legacy_bcrypt_hash_verifies_and_upgrades():
    legacy = passlib.hash.bcrypt.hash("legacypw")
    assert pwd_context.identify(legacy) == "bcrypt"

    ok, new_hash = pwd_context.verify_and_update("legacypw", legacy)
    assert ok
    # bcrypt is deprecated → verify_and_update returns a fresh bcrypt_sha256 hash.
    assert new_hash is not None
    assert pwd_context.identify(new_hash) == "bcrypt_sha256"
    assert pwd_context.verify("legacypw", new_hash)


def test_wrong_password_does_not_upgrade():
    legacy = passlib.hash.bcrypt.hash("legacypw")
    ok, new_hash = pwd_context.verify_and_update("WRONG", legacy)
    assert not ok
    assert new_hash is None
