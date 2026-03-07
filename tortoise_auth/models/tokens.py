"""Database-backed token models for opaque token storage."""

from __future__ import annotations

import hashlib

from tortoise import fields
from tortoise.models import Model
from tortoise.timezone import now as tz_now

from tortoise_auth.utils import generate_random_string


def hash_token(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw token string."""
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_token(length: int) -> str:
    """Generate a cryptographically secure random token."""
    return generate_random_string(length)


class AccessToken(Model):
    """Persisted opaque access token (stores SHA-256 hash, not the raw value)."""

    id = fields.IntField(primary_key=True)
    token_hash = fields.CharField(max_length=64, unique=True, db_index=True)
    jti = fields.CharField(max_length=64, unique=True, db_index=True)
    user_id = fields.CharField(max_length=255, db_index=True)
    created_at = fields.DatetimeField()
    expires_at = fields.DatetimeField()
    is_revoked = fields.BooleanField(default=False)

    class Meta:
        table = "tortoise_auth_access_tokens"

    @property
    def is_expired(self) -> bool:
        return tz_now() >= self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        return f"<AccessToken: jti={self.jti} user={self.user_id}>"


class RefreshToken(Model):
    """Persisted opaque refresh token (stores SHA-256 hash, not the raw value)."""

    id = fields.IntField(primary_key=True)
    token_hash = fields.CharField(max_length=64, unique=True, db_index=True)
    jti = fields.CharField(max_length=64, unique=True, db_index=True)
    user_id = fields.CharField(max_length=255, db_index=True)
    created_at = fields.DatetimeField()
    expires_at = fields.DatetimeField()
    is_revoked = fields.BooleanField(default=False)
    access_jti = fields.CharField(max_length=64, default="")

    class Meta:
        table = "tortoise_auth_refresh_tokens"

    @property
    def is_expired(self) -> bool:
        return tz_now() >= self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        return f"<RefreshToken: jti={self.jti} user={self.user_id}>"
