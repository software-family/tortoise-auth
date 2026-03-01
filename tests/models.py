"""Concrete test models for testing the abstract base class."""

from tortoise import fields

from tortoise_auth.models import AbstractUser


class MinimalUser(AbstractUser):
    """Minimal user model inheriting AbstractUser."""

    id = fields.IntField(primary_key=True)

    class Meta:
        table = "minimal_users"


class FullUser(AbstractUser):
    """User model with a custom phone field."""

    id = fields.IntField(primary_key=True)
    phone = fields.CharField(max_length=20, default="")

    class Meta:
        table = "full_users"
