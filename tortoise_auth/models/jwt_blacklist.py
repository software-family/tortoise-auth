"""JWT blacklist models for optional token revocation."""

from __future__ import annotations

from tortoise import fields
from tortoise.models import Model


class OutstandingToken(Model):
    """Tracks every JWT issued when blacklist is enabled."""

    id = fields.IntField(primary_key=True)
    jti = fields.CharField(max_length=64, unique=True, db_index=True)
    user_id = fields.CharField(max_length=255, db_index=True)
    token_type = fields.CharField(max_length=16)
    created_at = fields.DatetimeField()
    expires_at = fields.DatetimeField()

    class Meta:
        table = "tortoise_auth_outstanding_tokens"

    def __repr__(self) -> str:
        return f"<OutstandingToken: jti={self.jti} user={self.user_id}>"


class BlacklistedToken(Model):
    """Revoked JWT tokens."""

    id = fields.IntField(primary_key=True)
    jti = fields.CharField(max_length=64, unique=True, db_index=True)
    blacklisted_at = fields.DatetimeField(auto_now_add=True)

    class Meta:
        table = "tortoise_auth_blacklisted_tokens"

    def __repr__(self) -> str:
        return f"<BlacklistedToken: jti={self.jti}>"
