"""Abstract base user model for tortoise-auth."""

from __future__ import annotations

from tortoise import fields
from tortoise.models import Model

from tortoise_auth.config import get_config
from tortoise_auth.events import emit
from tortoise_auth.utils import is_password_usable, make_unusable_password


class AbstractUser(Model):
    """Abstract user model providing authentication and common fields."""

    email = fields.CharField(max_length=255, unique=True)
    password = fields.CharField(max_length=255, default="")
    last_login = fields.DatetimeField(null=True, default=None)
    is_active = fields.BooleanField(default=True)
    is_verified = fields.BooleanField(default=False)
    joined_at = fields.DatetimeField(null=True, default=None)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)

    class Meta:
        abstract = True

    async def set_password(self, raw_password: str) -> None:
        """Hash and save a new password, emitting a 'password_changed' event."""
        ph = get_config().get_password_hash()
        self.password = ph.hash(raw_password)
        await self.save(update_fields=["password"])
        await emit("password_changed", self)

    async def check_password(self, raw_password: str) -> bool:
        """Verify a password against the stored hash.

        Transparently migrates the hash if a non-primary hasher was used.
        Returns False for unusable passwords.
        """
        if not is_password_usable(self.password):
            return False

        ph = get_config().get_password_hash()
        try:
            valid, updated_hash = ph.verify_and_update(raw_password, self.password)
        except Exception:
            return False

        if valid and updated_hash is not None:
            self.password = updated_hash
            await self.save(update_fields=["password"])

        return valid

    def set_unusable_password(self) -> None:
        """Mark password as unusable (does NOT save to database)."""
        self.password = make_unusable_password()

    def has_usable_password(self) -> bool:
        """Check if this user has a usable password."""
        return is_password_usable(self.password)

    @property
    def is_authenticated(self) -> bool:
        """Always returns True for real user instances."""
        return True

    @property
    def is_anonymous(self) -> bool:
        """Always returns False for real user instances."""
        return False

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: {self.email}>"
