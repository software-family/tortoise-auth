"""Database-backed challenge storage backend."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.passkey.challenge import ChallengeData


class DatabaseChallengeBackend:
    """Challenge storage backend that persists challenges in the database."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def store(self, challenge_id: str, data: ChallengeData) -> None:
        """Store a challenge in the database."""
        from tortoise_auth.models.passkey import WebAuthnChallenge

        ttl = self.config.passkey_challenge_ttl
        now = datetime.now(tz=timezone.utc)
        await WebAuthnChallenge.create(
            challenge_id=challenge_id,
            challenge=data.challenge,
            user_id=data.user_id or "",
            expires_at=now + timedelta(seconds=ttl),
        )

    async def retrieve(self, challenge_id: str) -> ChallengeData | None:
        """Retrieve a challenge, returning None if expired or not found."""
        from tortoise_auth.models.passkey import WebAuthnChallenge

        row = await WebAuthnChallenge.filter(challenge_id=challenge_id).first()
        if row is None:
            return None
        now = datetime.now(tz=timezone.utc)
        if row.expires_at <= now:
            await row.delete()
            return None
        return ChallengeData(
            challenge=bytes(row.challenge),
            user_id=row.user_id or None,
            created_at=row.created_at.timestamp(),
        )

    async def delete(self, challenge_id: str) -> None:
        """Delete a challenge from the database."""
        from tortoise_auth.models.passkey import WebAuthnChallenge

        await WebAuthnChallenge.filter(challenge_id=challenge_id).delete()

    async def cleanup_expired(self) -> int:
        """Delete expired challenges. Returns count deleted."""
        from tortoise_auth.models.passkey import WebAuthnChallenge

        now = datetime.now(tz=timezone.utc)
        return await WebAuthnChallenge.filter(expires_at__lt=now).delete()
