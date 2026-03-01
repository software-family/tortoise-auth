"""Database-backed token models for tortoise-auth."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from tortoise import fields

if TYPE_CHECKING:
    from datetime import datetime
from tortoise.models import Model

from tortoise_auth import utils as tz_utils


class TokenMixin:
    """Shared logic for token models."""

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """SHA-256 hex digest of a raw token."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_token(length: int = 64) -> str:
        """Generate a cryptographically secure random token."""
        return tz_utils.generate_random_string(length)


class AccessToken(Model, TokenMixin):
    """Persisted access token."""

    id = fields.IntField(primary_key=True)
    token_hash = fields.CharField(max_length=64, unique=True, db_index=True)
    jti = fields.CharField(max_length=64, unique=True, db_index=True)
    user_id = fields.CharField(max_length=255, db_index=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()
    is_revoked = fields.BooleanField(default=False)

    @property
    def is_expired(self) -> bool:
        from tortoise.timezone import now as tz_now

        return self.expires_at < tz_now()

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    class Meta:
        table = "tortoise_auth_access_tokens"

    def __repr__(self) -> str:
        return f"<AccessToken: jti={self.jti} user={self.user_id}>"


class RefreshToken(Model, TokenMixin):
    """Persisted refresh token."""

    id = fields.IntField(primary_key=True)
    token_hash = fields.CharField(max_length=64, unique=True, db_index=True)
    jti = fields.CharField(max_length=64, unique=True, db_index=True)
    user_id = fields.CharField(max_length=255, db_index=True)
    access_jti = fields.CharField(max_length=64, default="")
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()
    is_revoked = fields.BooleanField(default=False)

    @property
    def is_expired(self) -> bool:
        from tortoise.timezone import now as tz_now

        return self.expires_at < tz_now()

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    class Meta:
        table = "tortoise_auth_refresh_tokens"

    def __repr__(self) -> str:
        return f"<RefreshToken: jti={self.jti} user={self.user_id}>"


def is_token_expired_at(expires_at: datetime) -> bool:
    """Check if a token has expired based on its expiration datetime."""
    from tortoise.timezone import now as tz_now

    return expires_at < tz_now()
