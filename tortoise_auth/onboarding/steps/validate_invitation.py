"""ValidateInvitationStep — validates an invitation token during onboarding."""

from __future__ import annotations

from typing import Any

from tortoise_auth.onboarding import ClientHint, FieldHint, StepContext, StepResult


class ValidateInvitationStep:
    """Onboarding step that validates an invitation token.

    Should be the first step in the pipeline when ``invitation_require``
    is ``True``.  On success, stores the email and invitation token in
    ``step_data`` so that subsequent steps can use the pre-validated email.
    """

    @property
    def name(self) -> str:
        return "validate_invitation"

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return context.config.invitation_require

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        from tortoise_auth.services.invitation import InvitationService

        token = data.get("invitation_token", "").strip()
        if not token:
            return StepResult(success=False, errors=["Invitation token is required"])

        service = InvitationService(config=context.config)
        try:
            invitation = await service.validate_invitation(token)
        except Exception as exc:
            return StepResult(success=False, errors=[str(exc)])

        return StepResult(
            success=True,
            data={
                "email": invitation.email,
                "invitation_token": token,
                "invited_by": invitation.invited_by,
                "invitation_role": invitation.role,
            },
        )

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(
            step_name=self.name,
            title="Accept your invitation",
            description="Enter the invitation token from your email.",
            fields=[
                FieldHint(
                    name="invitation_token",
                    field_type="text",
                    required=True,
                    label="Invitation token",
                    placeholder="Paste your invitation token",
                ),
            ],
        )