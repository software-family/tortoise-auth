"""WebAuthn/passkey credential and challenge models for tortoise-auth."""

from __future__ import annotations

from tortoise import fields
from tortoise.models import Model


class PasskeyCredential(Model):
    """Stores a registered WebAuthn credential linked to a user."""

    id = fields.IntField(primary_key=True)
    user_id = fields.CharField(max_length=255, db_index=True)

    # WebAuthn credential data
    credential_id = fields.BinaryField()
    credential_id_b64 = fields.CharField(max_length=512, unique=True, db_index=True)
    public_key = fields.BinaryField()
    sign_count = fields.IntField(default=0)

    # Credential metadata
    aaguid = fields.CharField(max_length=36, default="")
    credential_device_type = fields.CharField(max_length=32, default="")
    credential_backed_up = fields.BooleanField(default=False)

    # User-friendly metadata
    name = fields.CharField(max_length=255, default="")
    transports = fields.TextField(default="")  # JSON list

    # Timestamps
    created_at = fields.DatetimeField(auto_now_add=True)
    last_used_at = fields.DatetimeField(null=True, default=None)

    class Meta:
        table = "tortoise_auth_passkey_credentials"

    def __repr__(self) -> str:
        return f"<PasskeyCredential: id={self.id} user={self.user_id}>"


class WebAuthnChallenge(Model):
    """Short-lived WebAuthn challenge for the DatabaseChallengeBackend."""

    id = fields.IntField(primary_key=True)
    challenge_id = fields.CharField(max_length=64, unique=True, db_index=True)
    challenge = fields.BinaryField()
    user_id = fields.CharField(max_length=255, default="")
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField()

    class Meta:
        table = "tortoise_auth_webauthn_challenges"

    def __repr__(self) -> str:
        return f"<WebAuthnChallenge: id={self.id}>"
