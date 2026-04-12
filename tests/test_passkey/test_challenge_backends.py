"""Tests for WebAuthn challenge storage backends."""

from __future__ import annotations

import time

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.passkey.challenge import ChallengeData
from tortoise_auth.passkey.challenge_database import DatabaseChallengeBackend
from tortoise_auth.passkey.challenge_memory import InMemoryChallengeBackend


def make_config(**overrides: object) -> AuthConfig:
    defaults: dict[str, object] = {"passkey_challenge_ttl": 300}
    defaults.update(overrides)
    return AuthConfig(**defaults)  # type: ignore[arg-type]


def make_challenge_data(
    challenge: bytes = b"test-challenge-bytes",
    user_id: str | None = "user-123",
) -> ChallengeData:
    return ChallengeData(
        challenge=challenge,
        user_id=user_id,
        created_at=time.monotonic(),
    )


class TestInMemoryChallengeBackend:
    async def test_store_and_retrieve(self):
        backend = InMemoryChallengeBackend(make_config())
        data = make_challenge_data()
        await backend.store("chal-1", data)
        retrieved = await backend.retrieve("chal-1")
        assert retrieved is not None
        assert retrieved.challenge == b"test-challenge-bytes"
        assert retrieved.user_id == "user-123"

    async def test_retrieve_not_found(self):
        backend = InMemoryChallengeBackend(make_config())
        assert await backend.retrieve("nonexistent") is None

    async def test_retrieve_expired_returns_none(self):
        cfg = make_config(passkey_challenge_ttl=1)
        backend = InMemoryChallengeBackend(cfg)
        data = ChallengeData(
            challenge=b"expired",
            user_id="user-1",
            created_at=time.monotonic() - 2,  # 2 seconds ago, TTL is 1
        )
        await backend.store("chal-expired", data)
        assert await backend.retrieve("chal-expired") is None

    async def test_delete(self):
        backend = InMemoryChallengeBackend(make_config())
        data = make_challenge_data()
        await backend.store("chal-del", data)
        await backend.delete("chal-del")
        assert await backend.retrieve("chal-del") is None

    async def test_delete_nonexistent(self):
        backend = InMemoryChallengeBackend(make_config())
        await backend.delete("nonexistent")  # should not raise

    async def test_cleanup_expired(self):
        cfg = make_config(passkey_challenge_ttl=1)
        backend = InMemoryChallengeBackend(cfg)

        # Store an expired challenge
        expired_data = ChallengeData(
            challenge=b"old", user_id="u1", created_at=time.monotonic() - 2
        )
        await backend.store("expired", expired_data)

        # Store a fresh challenge
        fresh_data = make_challenge_data()
        await backend.store("fresh", fresh_data)

        removed = await backend.cleanup_expired()
        assert removed == 1
        assert await backend.retrieve("expired") is None
        assert await backend.retrieve("fresh") is not None

    async def test_store_with_none_user_id(self):
        backend = InMemoryChallengeBackend(make_config())
        data = make_challenge_data(user_id=None)
        await backend.store("chal-anon", data)
        retrieved = await backend.retrieve("chal-anon")
        assert retrieved is not None
        assert retrieved.user_id is None


class TestDatabaseChallengeBackend:
    async def test_store_and_retrieve(self):
        backend = DatabaseChallengeBackend(make_config())
        data = make_challenge_data()
        await backend.store("chal-1", data)
        retrieved = await backend.retrieve("chal-1")
        assert retrieved is not None
        assert retrieved.challenge == b"test-challenge-bytes"
        assert retrieved.user_id == "user-123"

    async def test_retrieve_not_found(self):
        backend = DatabaseChallengeBackend(make_config())
        assert await backend.retrieve("nonexistent") is None

    async def test_retrieve_expired_returns_none(self):
        cfg = make_config(passkey_challenge_ttl=0)
        backend = DatabaseChallengeBackend(cfg)
        # TTL=0 means challenge expires immediately
        data = make_challenge_data()
        await backend.store("chal-expired", data)
        # The challenge will be expired by the time we retrieve it
        import asyncio

        await asyncio.sleep(0.01)
        assert await backend.retrieve("chal-expired") is None

    async def test_delete(self):
        backend = DatabaseChallengeBackend(make_config())
        data = make_challenge_data()
        await backend.store("chal-del", data)
        await backend.delete("chal-del")
        assert await backend.retrieve("chal-del") is None

    async def test_delete_nonexistent(self):
        backend = DatabaseChallengeBackend(make_config())
        await backend.delete("nonexistent")  # should not raise

    async def test_cleanup_expired(self):
        cfg = make_config(passkey_challenge_ttl=0)
        backend = DatabaseChallengeBackend(cfg)

        data = make_challenge_data()
        await backend.store("old", data)

        import asyncio

        await asyncio.sleep(0.01)

        removed = await backend.cleanup_expired()
        assert removed >= 1

    async def test_store_with_none_user_id(self):
        backend = DatabaseChallengeBackend(make_config())
        data = make_challenge_data(user_id=None)
        await backend.store("chal-anon", data)
        retrieved = await backend.retrieve("chal-anon")
        assert retrieved is not None
        assert retrieved.user_id is None
