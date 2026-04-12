"""Invitation model for invitation-only registration."""

from __future__ import annotations

import hashlib

from tortoise import fields
from tortoise.models import Model
from tortoise.timezone import now as tz_now

from tortoise_auth.utils import generate_random_string


def hash_invitation_token(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw invitation token."""
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_invitation_token(length: int = 64) -> str:
    """Generate a cryptographically secure random invitation token."""
    return generate_random_string(length)


class Invitation(Model):
    """Tracks an invitation to join the platform (stores SHA-256 hash, not the raw token)."""

    id = fields.IntField(primary_key=True)
    token_hash = fields.CharField(max_length=64, unique=True, db_index=True)
    email = fields.CharField(max_length=255, db_index=True)
    invited_by = fields.CharField(max_length=255, default="")
    role = fields.CharField(max_length=64, default="")
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()
    accepted_at = fields.DatetimeField(null=True, default=None)
    revoked_at = fields.DatetimeField(null=True, default=None)

    class Meta:
        table = "tortoise_auth_invitations"

    @property
    def is_expired(self) -> bool:
        return tz_now() >= self.expires_at

    @property
    def is_accepted(self) -> bool:
        return self.accepted_at is not None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        return not self.is_expired and not self.is_accepted and not self.is_revoked

    def __repr__(self) -> str:
        return f"<Invitation: id={self.id} email={self.email}>"