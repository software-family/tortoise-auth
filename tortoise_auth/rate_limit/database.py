"""Database-backed rate limiting backend."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.rate_limit import RateLimitResult


class DatabaseRateLimitBackend:
    """Rate limiting backend that persists attempts in the database."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def check(self, key: str) -> RateLimitResult:
        """Check whether an attempt is allowed for the given key."""
        from tortoise_auth.models.rate_limit import LoginAttempt

        cfg = self.config
        window_start = datetime.now(tz=UTC) - timedelta(seconds=cfg.rate_limit_window)
        total = await LoginAttempt.filter(
            identifier=key,
            attempted_at__gte=window_start,
        ).count()

        max_attempts = cfg.rate_limit_max_attempts

        if total >= max_attempts:
            oldest = (
                await LoginAttempt.filter(
                    identifier=key,
                    attempted_at__gte=window_start,
                )
                .order_by("attempted_at")
                .first()
            )
            if oldest:
                retry_after = int(
                    (
                        oldest.attempted_at
                        + timedelta(seconds=cfg.rate_limit_lockout)
                        - datetime.now(tz=UTC)
                    ).total_seconds()
                )
                retry_after = max(retry_after, 1)
            else:
                retry_after = cfg.rate_limit_lockout
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
        from tortoise_auth.models.rate_limit import LoginAttempt

        await LoginAttempt.create(
            identifier=key,
            attempted_at=datetime.now(tz=UTC),
        )

    async def reset(self, key: str) -> None:
        """Clear all attempts for a key (on successful login)."""
        from tortoise_auth.models.rate_limit import LoginAttempt

        await LoginAttempt.filter(identifier=key).delete()

    async def cleanup_expired(self) -> int:
        """Delete expired attempt records. Returns count deleted."""
        from tortoise_auth.models.rate_limit import LoginAttempt

        cutoff = datetime.now(tz=UTC) - timedelta(seconds=self.config.rate_limit_window)
        return await LoginAttempt.filter(attempted_at__lt=cutoff).delete()
