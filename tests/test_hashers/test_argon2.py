"""Tests for the Argon2 hasher."""

from tortoise_auth.hashers.argon2 import Argon2Hasher, default_hasher


class TestArgon2Hasher:
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
        assert Argon2Hasher.identify(hashed)

    def test_hash_format(self):
        hasher = default_hasher()
        hashed = hasher.hash("test")
        assert hashed.startswith("$argon2id$")

    def test_random_salts(self):
        hasher = default_hasher()
        h1 = hasher.hash("same_password")
        h2 = hasher.hash("same_password")
        assert h1 != h2

    def test_custom_params(self):
        hasher = default_hasher(time_cost=2, memory_cost=32768, parallelism=2)
        hashed = hasher.hash("test")
        assert hasher.verify("test", hashed)

    def test_does_not_identify_bcrypt(self):
        from tortoise_auth.hashers.bcrypt import default_hasher as bcrypt_default

        bcrypt_hash = bcrypt_default().hash("test")
        assert not Argon2Hasher.identify(bcrypt_hash)

    def test_check_needs_rehash_different_params(self):
        hasher_old = default_hasher(time_cost=2)
        hasher_new = default_hasher(time_cost=3)
        hashed = hasher_old.hash("test")
        assert hasher_new.check_needs_rehash(hashed)

    def test_check_needs_rehash_same_params(self):
        hasher = default_hasher()
        hashed = hasher.hash("test")
        assert not hasher.check_needs_rehash(hashed)
