"""Tests for the database rate limiting backend."""

from datetime import datetime, timedelta, timezone

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.models.rate_limit import LoginAttempt
from tortoise_auth.rate_limit import RateLimitBackend
from tortoise_auth.rate_limit.database import DatabaseRateLimitBackend


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(rate_limit_max_attempts=3, rate_limit_window=60, rate_limit_lockout=120)


@pytest.fixture()
def backend(config: AuthConfig) -> DatabaseRateLimitBackend:
    return DatabaseRateLimitBackend(config)


class TestDatabaseProtocol:
    def test_implements_protocol(self, backend: DatabaseRateLimitBackend) -> None:
        assert isinstance(backend, RateLimitBackend)


class TestDatabaseCheck:
    async def test_allowed_when_no_attempts(self, backend: DatabaseRateLimitBackend) -> None:
        result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.remaining == 3
        assert result.retry_after == 0
        assert result.total_attempts == 0

    async def test_allowed_with_some_attempts(self, backend: DatabaseRateLimitBackend) -> None:
        await backend.record("user@example.com")
        await backend.record("user@example.com")
        result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.remaining == 1
        assert result.total_attempts == 2

    async def test_blocked_after_max_attempts(self, backend: DatabaseRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user@example.com")
        result = await backend.check("user@example.com")
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after > 0
        assert result.total_attempts == 3

    async def test_independent_keys(self, backend: DatabaseRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user1@example.com")
        result1 = await backend.check("user1@example.com")
        result2 = await backend.check("user2@example.com")
        assert result1.allowed is False
        assert result2.allowed is True

    async def test_old_attempts_outside_window(self, backend: DatabaseRateLimitBackend) -> None:
        # Create attempts outside the window using explicit timestamps
        old_time = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
        for _ in range(3):
            await LoginAttempt.create(
                identifier="user@example.com",
                attempted_at=old_time,
            )
        result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.total_attempts == 0


class TestDatabaseRecord:
    async def test_record_creates_entry(self, backend: DatabaseRateLimitBackend) -> None:
        await backend.record("user@example.com")
        count = await LoginAttempt.filter(identifier="user@example.com").count()
        assert count == 1

    async def test_record_sets_fields(self, backend: DatabaseRateLimitBackend) -> None:
        await backend.record("user@example.com")
        attempt = await LoginAttempt.filter(identifier="user@example.com").first()
        assert attempt is not None
        assert attempt.identifier == "user@example.com"
        assert attempt.attempted_at is not None


class TestDatabaseReset:
    async def test_reset_deletes_attempts(self, backend: DatabaseRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user@example.com")
        await backend.reset("user@example.com")
        count = await LoginAttempt.filter(identifier="user@example.com").count()
        assert count == 0
        result = await backend.check("user@example.com")
        assert result.allowed is True

    async def test_reset_nonexistent_key(self, backend: DatabaseRateLimitBackend) -> None:
        # Should not raise
        await backend.reset("nobody@example.com")

    async def test_reset_only_affects_target_key(self, backend: DatabaseRateLimitBackend) -> None:
        await backend.record("user1@example.com")
        await backend.record("user2@example.com")
        await backend.reset("user1@example.com")
        count1 = await LoginAttempt.filter(identifier="user1@example.com").count()
        count2 = await LoginAttempt.filter(identifier="user2@example.com").count()
        assert count1 == 0
        assert count2 == 1


class TestDatabaseCleanup:
    async def test_cleanup_removes_expired(self, backend: DatabaseRateLimitBackend) -> None:
        old_time = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
        await LoginAttempt.create(identifier="old@example.com", attempted_at=old_time)
        await backend.record("new@example.com")
        deleted = await backend.cleanup_expired()
        assert deleted == 1
        # New entry should still exist
        count = await LoginAttempt.filter(identifier="new@example.com").count()
        assert count == 1

    async def test_cleanup_keeps_active(self, backend: DatabaseRateLimitBackend) -> None:
        await backend.record("user@example.com")
        deleted = await backend.cleanup_expired()
        assert deleted == 0
