"""Rate limiting models for tortoise-auth."""

from tortoise import fields
from tortoise.models import Model


class LoginAttempt(Model):
    """Records a failed login attempt for rate limiting."""

    id = fields.IntField(primary_key=True)
    identifier = fields.CharField(max_length=255, db_index=True)
    attempted_at = fields.DatetimeField()
    ip_address = fields.CharField(max_length=45, default="", db_index=True)

    class Meta:
        table = "tortoise_auth_login_attempts"
