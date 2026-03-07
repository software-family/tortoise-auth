"""Tests for the in-memory rate limiting backend."""

import time
from unittest.mock import patch

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.rate_limit import RateLimitBackend, RateLimitResult
from tortoise_auth.rate_limit.memory import InMemoryRateLimitBackend


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(rate_limit_max_attempts=3, rate_limit_window=60, rate_limit_lockout=120)


@pytest.fixture()
def backend(config: AuthConfig) -> InMemoryRateLimitBackend:
    return InMemoryRateLimitBackend(config)


class TestInMemoryProtocol:
    def test_implements_protocol(self, backend: InMemoryRateLimitBackend) -> None:
        assert isinstance(backend, RateLimitBackend)


class TestInMemoryCheck:
    async def test_allowed_when_no_attempts(self, backend: InMemoryRateLimitBackend) -> None:
        result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.remaining == 3
        assert result.retry_after == 0
        assert result.total_attempts == 0

    async def test_allowed_with_some_attempts(self, backend: InMemoryRateLimitBackend) -> None:
        await backend.record("user@example.com")
        await backend.record("user@example.com")
        result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.remaining == 1
        assert result.total_attempts == 2

    async def test_blocked_after_max_attempts(self, backend: InMemoryRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user@example.com")
        result = await backend.check("user@example.com")
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after > 0
        assert result.total_attempts == 3

    async def test_independent_keys(self, backend: InMemoryRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user1@example.com")
        result1 = await backend.check("user1@example.com")
        result2 = await backend.check("user2@example.com")
        assert result1.allowed is False
        assert result2.allowed is True

    async def test_attempts_expire_after_window(self, backend: InMemoryRateLimitBackend) -> None:
        now = time.monotonic()
        # Simulate attempts made 61 seconds ago (window is 60s)
        with patch("tortoise_auth.rate_limit.memory.time") as mock_time:
            mock_time.monotonic.return_value = now - 61
            for _ in range(3):
                await backend.record("user@example.com")

        with patch("tortoise_auth.rate_limit.memory.time") as mock_time:
            mock_time.monotonic.return_value = now
            result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.total_attempts == 0


class TestInMemoryRecord:
    async def test_record_increments_count(self, backend: InMemoryRateLimitBackend) -> None:
        await backend.record("user@example.com")
        result = await backend.check("user@example.com")
        assert result.total_attempts == 1

    async def test_record_multiple(self, backend: InMemoryRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user@example.com")
        result = await backend.check("user@example.com")
        assert result.total_attempts == 3


class TestInMemoryReset:
    async def test_reset_clears_attempts(self, backend: InMemoryRateLimitBackend) -> None:
        for _ in range(3):
            await backend.record("user@example.com")
        await backend.reset("user@example.com")
        result = await backend.check("user@example.com")
        assert result.allowed is True
        assert result.total_attempts == 0

    async def test_reset_nonexistent_key(self, backend: InMemoryRateLimitBackend) -> None:
        # Should not raise
        await backend.reset("nobody@example.com")


class TestInMemoryCleanup:
    async def test_cleanup_removes_expired(self, backend: InMemoryRateLimitBackend) -> None:
        now = time.monotonic()
        with patch("tortoise_auth.rate_limit.memory.time") as mock_time:
            mock_time.monotonic.return_value = now - 61
            await backend.record("old@example.com")

        with patch("tortoise_auth.rate_limit.memory.time") as mock_time:
            mock_time.monotonic.return_value = now
            await backend.record("new@example.com")

        with patch("tortoise_auth.rate_limit.memory.time") as mock_time:
            mock_time.monotonic.return_value = now
            removed = await backend.cleanup_expired()
        assert removed == 1

    async def test_cleanup_keeps_active(self, backend: InMemoryRateLimitBackend) -> None:
        await backend.record("user@example.com")
        removed = await backend.cleanup_expired()
        assert removed == 0
        result = await backend.check("user@example.com")
        assert result.total_attempts == 1


class TestRateLimitResult:
    def test_frozen(self) -> None:
        result = RateLimitResult(allowed=True, remaining=5, retry_after=0, total_attempts=0)
        with pytest.raises(AttributeError):
            result.allowed = False  # type: ignore[misc]
