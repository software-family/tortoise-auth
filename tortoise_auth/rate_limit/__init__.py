"""Rate limiting backends and data types for tortoise-auth."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    retry_after: int
    total_attempts: int


@runtime_checkable
class RateLimitBackend(Protocol):
    """Protocol for rate limiting backends."""

    async def check(self, key: str) -> RateLimitResult: ...
    async def record(self, key: str) -> None: ...
    async def reset(self, key: str) -> None: ...
    async def cleanup_expired(self) -> int: ...
