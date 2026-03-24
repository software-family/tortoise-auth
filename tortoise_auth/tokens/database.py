"""Database-backed opaque token backend."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.tokens import TokenPair, TokenPayload


class DatabaseTokenBackend:
    """Opaque token backend that persists SHA-256 hashed tokens in the database."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair:
        """Generate random opaque tokens, hash and store them, return raw strings."""
        from tortoise_auth.models.tokens import (
            AccessToken,
            RefreshToken,
            generate_token,
            hash_token,
        )

        cfg = self.config
        now = datetime.now(tz=timezone.utc)

        access_raw = generate_token(cfg.token_length)
        access_jti = uuid.uuid4().hex
        await AccessToken.create(
            token_hash=hash_token(access_raw),
            jti=access_jti,
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(seconds=cfg.access_token_lifetime),
        )

        refresh_raw = generate_token(cfg.token_length)
        refresh_jti = uuid.uuid4().hex
        await RefreshToken.create(
            token_hash=hash_token(refresh_raw),
            jti=refresh_jti,
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(seconds=cfg.refresh_token_lifetime),
            access_jti=access_jti,
        )

        return TokenPair(access_token=access_raw, refresh_token=refresh_raw)

    async def verify_token(self, token: str, *, token_type: str = "access") -> TokenPayload:
        """Hash the raw token, look it up, and validate it."""
        if token_type not in ("access", "refresh"):
            raise TokenInvalidError(f"Unknown token type: {token_type!r}")

        from tortoise_auth.models.tokens import AccessToken, RefreshToken, hash_token

        token_hash = hash_token(token)
        model = AccessToken if token_type == "access" else RefreshToken
        record = await model.filter(token_hash=token_hash).first()

        if record is None:
            raise TokenInvalidError("Token not found")

        if record.is_revoked:
            raise TokenRevokedError("Token has been revoked")

        if record.is_expired:
            raise TokenExpiredError("Token has expired")

        return TokenPayload(
            sub=record.user_id,
            token_type=token_type,
            jti=record.jti,
            iat=int(record.created_at.timestamp()),
            exp=int(record.expires_at.timestamp()),
            extra=None,
        )

    async def revoke_token(self, token: str) -> None:
        """Revoke a token by its raw value. No-op if not found."""
        from tortoise_auth.models.tokens import AccessToken, RefreshToken, hash_token

        token_hash = hash_token(token)

        updated = await AccessToken.filter(token_hash=token_hash).update(is_revoked=True)
        if updated:
            return

        await RefreshToken.filter(token_hash=token_hash).update(is_revoked=True)

    async def revoke_all_for_user(self, user_id: str) -> None:
        """Revoke all tokens for a given user."""
        from tortoise_auth.models.tokens import AccessToken, RefreshToken

        await AccessToken.filter(user_id=user_id, is_revoked=False).update(is_revoked=True)
        await RefreshToken.filter(user_id=user_id, is_revoked=False).update(is_revoked=True)

    async def cleanup_expired(self) -> int:
        """Delete expired token rows, return count deleted."""
        from tortoise_auth.models.tokens import AccessToken, RefreshToken

        now = datetime.now(tz=timezone.utc)
        access_deleted = await AccessToken.filter(expires_at__lt=now).delete()
        refresh_deleted = await RefreshToken.filter(expires_at__lt=now).delete()
        return access_deleted + refresh_deleted
