"""Tests for the Bcrypt hasher."""

from tortoise_auth.hashers.bcrypt import BcryptHasher, default_hasher


class TestBcryptHasher:
    def test_hash_and_verify(self):
        hasher = default_hasher()
        hashed = hasher.hash("my_password")
        assert hasher.verify("my_password", hashed)

    def test_wrong_password(self):
        hasher = default_hasher()
        hashed = hasher.hash("correct")
        assert not hasher.verify("wrong", hashed)

    def test_identify(self):
        hasher = default_hasher()
        hashed = hasher.hash("test")
        assert BcryptHasher.identify(hashed)

    def test_hash_format(self):
        hasher = default_hasher()
        hashed = hasher.hash("test")
        assert hashed.startswith("$2b$")

    def test_random_salts(self):
        hasher = default_hasher()
        h1 = hasher.hash("same_password")
        h2 = hasher.hash("same_password")
        assert h1 != h2

    def test_custom_rounds(self):
        hasher = default_hasher(rounds=4)
        hashed = hasher.hash("test")
        assert hasher.verify("test", hashed)
        assert "$04$" in hashed

    def test_does_not_identify_argon2(self):
        from tortoise_auth.hashers.argon2 import default_hasher as argon2_default

        argon2_hash = argon2_default().hash("test")
        assert not BcryptHasher.identify(argon2_hash)

    def test_check_needs_rehash_different_rounds(self):
        hasher_old = default_hasher(rounds=4)
        hasher_new = default_hasher(rounds=12)
        hashed = hasher_old.hash("test")
        assert hasher_new.check_needs_rehash(hashed)
