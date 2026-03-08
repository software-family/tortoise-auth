"""SetupTOTPStep — optional TOTP setup during onboarding."""

from __future__ import annotations

from typing import Any

from tortoise import Tortoise

from tortoise_auth.onboarding import ClientHint, FieldHint, StepContext, StepResult


class SetupTOTPStep:
    """Onboarding step for setting up TOTP-based two-factor authentication.

    Two-phase step:
    - Phase 1 (no code in data): generates TOTP secret and provisioning URI
    - Phase 2 (code in data): verifies the TOTP code and persists the secret
    """

    @property
    def name(self) -> str:
        return "setup_totp"

    @property
    def skippable(self) -> bool:
        return True

    async def is_required(self, context: StepContext) -> bool:
        return context.config.onboarding_require_totp

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        try:
            import pyotp
        except ImportError:
            return StepResult(
                success=False,
                errors=["pyotp is required for TOTP setup. Install it with: pip install pyotp"],
            )

        code = data.get("code", "").strip()

        if not code:
            return self._generate_secret(context, pyotp)
        return await self._verify_code(context, code, pyotp)

    def client_hint(self, context: StepContext) -> ClientHint:
        secret = context.step_data.get("_totp_secret")
        if secret:
            return ClientHint(
                step_name=self.name,
                title="Verify authenticator",
                description="Enter the 6-digit code from your authenticator app.",
                skippable=self.skippable,
                fields=[
                    FieldHint(
                        name="code",
                        field_type="code",
                        required=True,
                        label="TOTP code",
                        placeholder="000000",
                        validation={"length": 6, "pattern": r"^\d{6}$"},
                    ),
                ],
                extra={
                    "provisioning_uri": context.step_data.get("_totp_provisioning_uri", ""),
                    "secret": secret,
                },
            )
        return ClientHint(
            step_name=self.name,
            title="Set up two-factor authentication",
            description="Scan the QR code with your authenticator app.",
            skippable=self.skippable,
            fields=[],
            extra={"action": "generate_secret"},
        )

    def _generate_secret(self, context: StepContext, pyotp: Any) -> StepResult:
        """Generate a TOTP secret and provisioning URI."""
        secret = pyotp.random_base32()

        email = context.step_data.get("email", "")
        issuer = context.config.jwt_issuer or "tortoise-auth"
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name=issuer)

        return StepResult(
            success=True,
            completed=False,
            data={
                "_totp_secret": secret,
                "_totp_provisioning_uri": provisioning_uri,
            },
        )

    async def _verify_code(self, context: StepContext, code: str, pyotp: Any) -> StepResult:
        """Verify the TOTP code and persist the secret on the user."""
        secret = context.step_data.get("_totp_secret", "")
        if not secret:
            return StepResult(success=False, errors=["No TOTP secret generated"])

        totp = pyotp.TOTP(secret)
        if not totp.verify(code):
            return StepResult(success=False, errors=["Invalid TOTP code"])

        # Persist secret on user if the user model has a totp_secret field
        user_id = context.user_id
        if user_id:
            user_model = self._resolve_user_model(context)
            user = await user_model.filter(pk=user_id).first()
            if user and hasattr(user, "totp_secret"):
                user.totp_secret = secret
                await user.save(update_fields=["totp_secret"])

        return StepResult(
            success=True,
            data={"totp_enabled": True},
        )

    def _resolve_user_model(self, context: StepContext) -> Any:
        model_path = context.config.user_model
        app_label, model_name = model_path.rsplit(".", 1)
        return Tortoise.apps[app_label][model_name]
