"""Invitation service for tortoise-auth."""

from __future__ import annotations

from datetime import timedelta

from tortoise.timezone import now as tz_now

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import (
    InvitationAlreadyAcceptedError,
    InvitationError,
    InvitationExpiredError,
    InvitationNotFoundError,
    InvitationRevokedError,
)
from tortoise_auth.models.invitation import Invitation, hash_invitation_token
from tortoise_auth.signing import make_token, verify_token


class InvitationService:
    """High-level service for managing invitations."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def create_invitation(
        self,
        email: str,
        *,
        invited_by: str = "",
        role: str = "",
    ) -> str:
        """Create an invitation and return the raw signed token.

        Emits ``invitation_created`` with *email*, *token*, *invited_by*, *role*.
        """
        max_pending = self.config.invitation_max_pending
        if max_pending > 0:
            pending_count = await Invitation.filter(
                email=email,
                accepted_at=None,
                revoked_at=None,
                expires_at__gt=tz_now(),
            ).count()
            if pending_count >= max_pending:
                raise InvitationError(
                    f"Maximum pending invitations ({max_pending}) reached for {email}"
                )

        token = make_token(email, self.config.effective_signing_secret)
        token_hash = hash_invitation_token(token)
        expires_at = tz_now() + timedelta(seconds=self.config.invitation_token_lifetime)

        await Invitation.create(
            token_hash=token_hash,
            email=email,
            invited_by=invited_by,
            role=role,
            expires_at=expires_at,
        )

        await emit(
            "invitation_created",
            email=email,
            token=token,
            invited_by=invited_by,
            role=role,
        )

        return token

    async def validate_invitation(self, token: str) -> Invitation:
        """Validate a token and return the Invitation record.

        Does NOT mark as accepted — call :meth:`accept_invitation` after
        the onboarding flow completes.
        """
        verify_token(
            token,
            max_age=self.config.invitation_token_lifetime,
            secret=self.config.effective_signing_secret,
        )

        token_hash = hash_invitation_token(token)
        invitation = await Invitation.filter(token_hash=token_hash).first()

        if invitation is None:
            raise InvitationNotFoundError("Invitation not found")

        if invitation.is_revoked:
            raise InvitationRevokedError("Invitation has been revoked")

        if invitation.is_accepted:
            raise InvitationAlreadyAcceptedError("Invitation has already been used")

        if invitation.is_expired:
            raise InvitationExpiredError("Invitation has expired")

        return invitation

    async def accept_invitation(self, token: str) -> Invitation:
        """Mark an invitation as accepted. Called after successful onboarding."""
        invitation = await self.validate_invitation(token)
        invitation.accepted_at = tz_now()
        await invitation.save(update_fields=["accepted_at"])

        await emit(
            "invitation_accepted",
            email=invitation.email,
            invitation_id=str(invitation.id),
        )

        return invitation

    async def revoke_invitation(self, invitation_id: int) -> None:
        """Revoke a pending invitation."""
        invitation = await Invitation.filter(id=invitation_id).first()
        if invitation is None:
            raise InvitationNotFoundError("Invitation not found")

        invitation.revoked_at = tz_now()
        await invitation.save(update_fields=["revoked_at"])

        await emit(
            "invitation_revoked",
            email=invitation.email,
            invitation_id=str(invitation.id),
        )

    async def list_pending(self, email: str | None = None) -> list[Invitation]:
        """List pending (not accepted, not revoked, not expired) invitations."""
        qs = Invitation.filter(
            accepted_at=None,
            revoked_at=None,
            expires_at__gt=tz_now(),
        )
        if email:
            qs = qs.filter(email=email)
        return await qs.all()

    async def cleanup_expired(self) -> int:
        """Delete expired invitations. Returns number deleted."""
        return await Invitation.filter(expires_at__lt=tz_now()).delete()
