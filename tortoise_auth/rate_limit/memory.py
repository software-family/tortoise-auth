"""In-memory rate limiting backend."""

from __future__ import annotations

import time

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.rate_limit import RateLimitResult


class InMemoryRateLimitBackend:
    """Rate limiting backend that stores attempts in memory."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config
        self._attempts: dict[str, list[float]] = {}

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    def _prune(self, key: str) -> list[float]:
        """Remove expired timestamps for a key and return remaining."""
        timestamps = self._attempts.get(key, [])
        if not timestamps:
            return []
        cutoff = time.monotonic() - self.config.rate_limit_window
        active = [t for t in timestamps if t > cutoff]
        if active:
            self._attempts[key] = active
        else:
            self._attempts.pop(key, None)
        return active

    async def check(self, key: str) -> RateLimitResult:
        """Check whether an attempt is allowed for the given key."""
        active = self._prune(key)
        total = len(active)
        max_attempts = self.config.rate_limit_max_attempts

        if total >= max_attempts:
            oldest = active[0]
            retry_after = int(oldest + self.config.rate_limit_lockout - time.monotonic())
            retry_after = max(retry_after, 1)
            return RateLimitResult(
                allowed=False,
                remaining=0,
                retry_after=retry_after,
                total_attempts=total,
            )

        return RateLimitResult(
            allowed=True,
            remaining=max_attempts - total,
            retry_after=0,
            total_attempts=total,
        )

    async def record(self, key: str) -> None:
        """Record a failed attempt."""
        self._attempts.setdefault(key, []).append(time.monotonic())

    async def reset(self, key: str) -> None:
        """Clear all attempts for a key (on successful login)."""
        self._attempts.pop(key, None)

    async def cleanup_expired(self) -> int:
        """Purge expired entries. Returns number of keys fully removed."""
        removed = 0
        cutoff = time.monotonic() - self.config.rate_limit_window
        for key in list(self._attempts):
            active = [t for t in self._attempts[key] if t > cutoff]
            if active:
                self._attempts[key] = active
            else:
                del self._attempts[key]
                removed += 1
        return removed
