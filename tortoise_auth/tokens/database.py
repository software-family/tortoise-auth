"""Database-backed token backend using Tortoise ORM models."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.models.tokens import AccessToken, RefreshToken
from tortoise_auth.tokens import TokenPair, TokenPayload


class DatabaseTokenBackend:
    """Token backend that persists tokens in the database for immediate revocation."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair:
        """Create and persist an access/refresh token pair."""
        cfg = self.config
        now = time.time()
        now_dt = datetime.fromtimestamp(now, tz=UTC)

        access_raw = AccessToken.generate_token(cfg.db_token_length)
        access_jti = uuid.uuid4().hex
        access_expires = datetime.fromtimestamp(
            now + cfg.jwt_access_token_lifetime, tz=UTC
        )
        await AccessToken.create(
            token_hash=AccessToken.hash_token(access_raw),
            jti=access_jti,
            user_id=user_id,
            created_at=now_dt,
            expires_at=access_expires,
        )

        refresh_raw = RefreshToken.generate_token(cfg.db_token_length)
        refresh_jti = uuid.uuid4().hex
        refresh_expires = datetime.fromtimestamp(
            now + cfg.jwt_refresh_token_lifetime, tz=UTC
        )
        await RefreshToken.create(
            token_hash=RefreshToken.hash_token(refresh_raw),
            jti=refresh_jti,
            user_id=user_id,
            access_jti=access_jti,
            created_at=now_dt,
            expires_at=refresh_expires,
        )

        return TokenPair(access_token=access_raw, refresh_token=refresh_raw)

    async def verify_token(
        self, token: str, *, token_type: str = "access"
    ) -> TokenPayload:
        """Verify a database token by looking up its hash."""
        token_hash = AccessToken.hash_token(token)
        record: AccessToken | RefreshToken | None

        if token_type == "access":
            record = await AccessToken.filter(token_hash=token_hash).first()
        elif token_type == "refresh":
            record = await RefreshToken.filter(token_hash=token_hash).first()
        else:
            raise TokenInvalidError(f"Unknown token type: {token_type!r}")

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
        )

    async def revoke_token(self, token: str) -> None:
        """Revoke a single token (tries access first, then refresh)."""
        token_hash = AccessToken.hash_token(token)
        updated = await AccessToken.filter(token_hash=token_hash).update(is_revoked=True)
        if not updated:
            await RefreshToken.filter(token_hash=token_hash).update(is_revoked=True)

    async def revoke_all_for_user(self, user_id: str) -> None:
        """Revoke all tokens for a user."""
        await AccessToken.filter(user_id=user_id, is_revoked=False).update(is_revoked=True)
        await RefreshToken.filter(user_id=user_id, is_revoked=False).update(is_revoked=True)

    async def cleanup_expired(self) -> int:
        """Delete expired tokens. Returns count of deleted rows."""
        now = datetime.now(tz=UTC)
        access_deleted = await AccessToken.filter(expires_at__lt=now).delete()
        refresh_deleted = await RefreshToken.filter(expires_at__lt=now).delete()
        return access_deleted + refresh_deleted
