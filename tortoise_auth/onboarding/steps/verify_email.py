"""VerifyEmailStep — email verification via signed 6-digit code."""

from __future__ import annotations

import secrets
from typing import Any

from tortoise import Tortoise

from tortoise_auth.events import emit
from tortoise_auth.onboarding import ClientHint, FieldHint, StepContext, StepResult
from tortoise_auth.signing import TimestampSigner


class VerifyEmailStep:
    """Onboarding step that verifies the user's email address.

    Two-phase step:
    - Phase 1 (no code in data): generates and signs a 6-digit code, emits event
    - Phase 2 (code in data): verifies the code and marks user as verified
    """

    @property
    def name(self) -> str:
        return "verify_email"

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return not context.step_data.get("email_verified", False)

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        code = data.get("code", "").strip()

        if not code:
            return await self._send_code(context)
        return await self._verify_code(context, code)

    def client_hint(self, context: StepContext) -> ClientHint:
        if context.step_data.get("_verification_code_signed"):
            return ClientHint(
                step_name=self.name,
                title="Enter verification code",
                description="We sent a 6-digit code to your email.",
                fields=[
                    FieldHint(
                        name="code",
                        field_type="code",
                        required=True,
                        label="Verification code",
                        placeholder="000000",
                        validation={"length": 6, "pattern": r"^\d{6}$"},
                    ),
                ],
            )
        return ClientHint(
            step_name=self.name,
            title="Verify your email",
            description="Click below to receive a verification code.",
            fields=[],
            extra={"action": "send_code"},
        )

    async def _send_code(self, context: StepContext) -> StepResult:
        """Generate a 6-digit code, sign it, and emit event for the dev to send."""
        code = "".join(secrets.choice("0123456789") for _ in range(6))

        signer = TimestampSigner(context.config.effective_signing_secret)
        signed = signer.sign_with_timestamp(code)

        email = context.step_data.get("email", "")
        if not email:
            # Resolve from user
            user_id = context.user_id
            if user_id:
                user_model = self._resolve_user_model(context)
                user = await user_model.filter(pk=user_id).first()
                if user:
                    email = user.email

        await emit("verification_code_generated", email=email, code=code)

        return StepResult(
            success=True,
            completed=False,
            data={
                "_verification_code_signed": signed,
                "_verification_attempts": 0,
                "email": email,
            },
        )

    async def _verify_code(self, context: StepContext, code: str) -> StepResult:
        """Verify the code against the signed value."""
        signed = context.step_data.get("_verification_code_signed", "")
        if not signed:
            return StepResult(success=False, errors=["No verification code has been sent"])

        attempts = context.step_data.get("_verification_attempts", 0) + 1
        max_attempts = context.config.onboarding_max_verification_attempts

        if attempts > max_attempts:
            return StepResult(
                success=False,
                errors=["Maximum verification attempts exceeded"],
                data={"_verification_attempts": attempts, "_max_attempts_exceeded": True},
            )

        signer = TimestampSigner(context.config.effective_signing_secret)
        try:
            original_code = signer.unsign_with_timestamp(
                signed, max_age=context.config.onboarding_verification_code_ttl
            )
        except Exception:
            return StepResult(
                success=False,
                errors=["Verification code has expired. Please request a new one."],
                data={"_verification_code_signed": "", "_verification_attempts": 0},
            )

        if code != original_code:
            return StepResult(
                success=False,
                errors=["Invalid verification code"],
                data={"_verification_attempts": attempts},
            )

        # Mark user as verified
        user_id = context.user_id
        if user_id:
            user_model = self._resolve_user_model(context)
            user = await user_model.filter(pk=user_id).first()
            if user:
                user.is_verified = True
                await user.save(update_fields=["is_verified"])

        return StepResult(
            success=True,
            data={"email_verified": True},
        )

    def _resolve_user_model(self, context: StepContext) -> Any:
        model_path = context.config.user_model
        app_label, model_name = model_path.rsplit(".", 1)
        return Tortoise.apps[app_label][model_name]
