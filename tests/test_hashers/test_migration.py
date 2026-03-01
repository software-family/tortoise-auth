"""Tests for transparent hash migration via PasswordHash."""

from tortoise_auth.hashers import default_password_hash
from tortoise_auth.hashers.argon2 import Argon2Hasher
from tortoise_auth.hashers.bcrypt import default_hasher as bcrypt_default
from tortoise_auth.hashers.pbkdf2 import PBKDF2Hasher


class TestHashMigration:
    def test_bcrypt_to_argon2(self):
        bcrypt_hasher = bcrypt_default(rounds=4)
        bcrypt_hash = bcrypt_hasher.hash("password123")

        ph = default_password_hash()
        valid, updated = ph.verify_and_update("password123", bcrypt_hash)

        assert valid
        assert updated is not None
        assert Argon2Hasher.identify(updated)

    def test_pbkdf2_to_argon2(self):
        pbkdf2_hasher = PBKDF2Hasher()
        pbkdf2_hash = pbkdf2_hasher.hash("password123")

        ph = default_password_hash()
        valid, updated = ph.verify_and_update("password123", pbkdf2_hash)

        assert valid
        assert updated is not None
        assert Argon2Hasher.identify(updated)

    def test_argon2_not_migrated(self):
        ph = default_password_hash()
        argon2_hash = ph.hash("password123")

        valid, updated = ph.verify_and_update("password123", argon2_hash)

        assert valid
        assert updated is None  # no migration needed

    def test_wrong_password_no_migration(self):
        bcrypt_hasher = bcrypt_default(rounds=4)
        bcrypt_hash = bcrypt_hasher.hash("password123")

        ph = default_password_hash()
        valid, updated = ph.verify_and_update("wrong", bcrypt_hash)

        assert not valid
        assert updated is None
