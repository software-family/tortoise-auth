"""Onboarding session model for tracking multi-step onboarding flows."""

from __future__ import annotations

import hashlib

from tortoise import fields
from tortoise.models import Model
from tortoise.timezone import now as tz_now

from tortoise_auth.utils import generate_random_string


def hash_session_token(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw session token."""
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_session_token(length: int) -> str:
    """Generate a cryptographically secure random session token."""
    return generate_random_string(length)


class OnboardingSession(Model):
    """Tracks an in-progress onboarding flow (stores SHA-256 hash, not the raw token)."""

    id = fields.IntField(primary_key=True)
    token_hash = fields.CharField(max_length=64, unique=True, db_index=True)
    email = fields.CharField(max_length=255, db_index=True)
    user_id = fields.CharField(max_length=255, default="", db_index=True)
    pipeline = fields.TextField()
    current_step_index = fields.IntField(default=0)
    step_state = fields.TextField(default="{}")
    step_data = fields.TextField(default="{}")
    ip_address = fields.CharField(max_length=45, default="")
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()
    completed_at = fields.DatetimeField(null=True, default=None)
    is_invalidated = fields.BooleanField(default=False)

    class Meta:
        table = "tortoise_auth_onboarding_sessions"

    @property
    def is_expired(self) -> bool:
        return tz_now() >= self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_invalidated and not self.is_expired and self.completed_at is None

    def __repr__(self) -> str:
        return f"<OnboardingSession: id={self.id} email={self.email}>"
