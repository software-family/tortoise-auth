"""Challenge backend protocol and data types for WebAuthn passkey support."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class ChallengeData:
    """Stored challenge data."""

    challenge: bytes
    user_id: str | None
    created_at: float


@runtime_checkable
class ChallengeBackend(Protocol):
    """Protocol for WebAuthn challenge storage backends."""

    async def store(self, challenge_id: str, data: ChallengeData) -> None: ...
    async def retrieve(self, challenge_id: str) -> ChallengeData | None: ...
    async def delete(self, challenge_id: str) -> None: ...
    async def cleanup_expired(self) -> int: ...
