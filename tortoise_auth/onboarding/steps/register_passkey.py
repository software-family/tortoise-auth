"""RegisterPasskeyStep — optional passkey registration during onboarding."""

from __future__ import annotations

from typing import Any

from tortoise import Tortoise

from tortoise_auth.onboarding import ClientHint, FieldHint, StepContext, StepResult


class RegisterPasskeyStep:
    """Onboarding step for registering a passkey credential.

    Two-phase step:
    - Phase 1 (no credential in data): generates WebAuthn registration options
    - Phase 2 (credential in data): verifies the response and stores the credential
    """

    @property
    def name(self) -> str:
        return "register_passkey"

    @property
    def skippable(self) -> bool:
        return True

    async def is_required(self, context: StepContext) -> bool:
        return False  # Always optional — users may skip passkey setup

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        try:
            import webauthn  # noqa: F401
        except ImportError:
            return StepResult(
                success=False,
                errors=[
                    "webauthn is required for passkey setup. "
                    "Install it with: pip install tortoise-auth[passkey]"
                ],
            )

        credential = data.get("credential")

        if not credential:
            return await self._begin_registration(context)
        return await self._complete_registration(context, data)

    def client_hint(self, context: StepContext) -> ClientHint:
        challenge_id = context.step_data.get("_passkey_challenge_id")
        if challenge_id:
            return ClientHint(
                step_name=self.name,
                title="Complete passkey registration",
                description="Complete the passkey registration with your device.",
                skippable=self.skippable,
                fields=[
                    FieldHint(
                        name="credential",
                        field_type="webauthn_credential",
                        required=True,
                        label="Credential response",
                    ),
                    FieldHint(
                        name="name",
                        field_type="text",
                        required=False,
                        label="Credential name",
                        placeholder="My passkey",
                    ),
                ],
                extra={
                    "options": context.step_data.get("_passkey_options", ""),
                    "challenge_id": challenge_id,
                },
            )
        return ClientHint(
            step_name=self.name,
            title="Set up a passkey",
            description="Register a passkey for passwordless sign-in.",
            skippable=self.skippable,
            fields=[],
            extra={"action": "begin_registration"},
        )

    async def _begin_registration(self, context: StepContext) -> StepResult:
        """Generate WebAuthn registration options."""
        from tortoise_auth.passkey.service import PasskeyService

        user_id = context.user_id
        if not user_id:
            return StepResult(success=False, errors=["User not created yet"])

        user_model = self._resolve_user_model(context)
        user = await user_model.filter(pk=user_id).first()
        if not user:
            return StepResult(success=False, errors=["User not found"])

        service = PasskeyService(config=context.config)
        result = await service.begin_registration(user)

        return StepResult(
            success=True,
            completed=False,
            data={
                "_passkey_options": result["options"],
                "_passkey_challenge_id": result["challenge_id"],
            },
        )

    async def _complete_registration(
        self, context: StepContext, data: dict[str, Any]
    ) -> StepResult:
        """Verify the credential response and store the passkey."""
        from tortoise_auth.passkey.service import PasskeyService

        user_id = context.user_id
        if not user_id:
            return StepResult(success=False, errors=["User not created yet"])

        user_model = self._resolve_user_model(context)
        user = await user_model.filter(pk=user_id).first()
        if not user:
            return StepResult(success=False, errors=["User not found"])

        challenge_id = context.step_data.get("_passkey_challenge_id", "")
        if not challenge_id:
            return StepResult(success=False, errors=["No registration in progress"])

        service = PasskeyService(config=context.config)
        try:
            await service.complete_registration(
                user,
                credential=data["credential"],
                challenge_id=challenge_id,
                name=data.get("name", ""),
            )
        except Exception as exc:
            return StepResult(success=False, errors=[str(exc)])

        return StepResult(
            success=True,
            data={"passkey_registered": True},
        )

    def _resolve_user_model(self, context: StepContext) -> Any:
        model_path = context.config.user_model
        app_label, model_name = model_path.rsplit(".", 1)
        return Tortoise.apps[app_label][model_name]
