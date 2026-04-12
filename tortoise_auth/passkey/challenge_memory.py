"""In-memory challenge storage backend."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from tortoise_auth.config import AuthConfig, get_config

if TYPE_CHECKING:
    from tortoise_auth.passkey.challenge import ChallengeData


class InMemoryChallengeBackend:
    """Challenge storage backend that stores challenges in memory with TTL."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config
        self._store: dict[str, ChallengeData] = {}

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def store(self, challenge_id: str, data: ChallengeData) -> None:
        """Store a challenge."""
        self._store[challenge_id] = data

    async def retrieve(self, challenge_id: str) -> ChallengeData | None:
        """Retrieve a challenge, returning None if expired or not found."""
        data = self._store.get(challenge_id)
        if data is None:
            return None
        if time.monotonic() - data.created_at > self.config.passkey_challenge_ttl:
            del self._store[challenge_id]
            return None
        return data

    async def delete(self, challenge_id: str) -> None:
        """Delete a challenge."""
        self._store.pop(challenge_id, None)

    async def cleanup_expired(self) -> int:
        """Purge expired challenges. Returns number removed."""
        removed = 0
        cutoff = time.monotonic() - self.config.passkey_challenge_ttl
        for key in list(self._store):
            if self._store[key].created_at <= cutoff:
                del self._store[key]
                removed += 1
        return removed
