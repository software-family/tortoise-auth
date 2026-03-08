"""RegisterStep — creates a new user account during onboarding."""

from __future__ import annotations

import re
from typing import Any

from tortoise import Tortoise

from tortoise_auth.onboarding import ClientHint, FieldHint, StepContext, StepResult
from tortoise_auth.validators import validate_password

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


class RegisterStep:
    """Onboarding step that registers a new user."""

    @property
    def name(self) -> str:
        return "register"

    @property
    def skippable(self) -> bool:
        return False

    async def is_required(self, context: StepContext) -> bool:
        return True

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        email = data.get("email", "").strip()
        password = data.get("password", "")
        password_confirm = data.get("password_confirm", "")

        errors: list[str] = []

        if not email:
            errors.append("Email is required")
        elif not _EMAIL_RE.match(email):
            errors.append("Invalid email format")

        if not password:
            errors.append("Password is required")
        elif password != password_confirm:
            errors.append("Passwords do not match")

        if errors:
            return StepResult(success=False, errors=errors)

        # Validate password strength
        try:
            validate_password(password)
        except Exception as exc:
            if hasattr(exc, "errors"):
                errors.extend(exc.errors)
            else:
                errors.append(str(exc))
            return StepResult(success=False, errors=errors)

        # Resolve user model and check uniqueness
        user_model = self._resolve_user_model(context)
        existing = await user_model.filter(email=email).exists()
        if existing:
            return StepResult(success=False, errors=["Email already taken"])

        # Create user
        user = user_model(email=email, is_active=True, is_verified=False)
        await user.save()
        await user.set_password(password)

        return StepResult(
            success=True,
            data={"user_id": str(user.pk)},
        )

    def client_hint(self, context: StepContext) -> ClientHint:
        return ClientHint(
            step_name=self.name,
            title="Create your account",
            description="Enter your email and choose a password.",
            fields=[
                FieldHint(
                    name="email",
                    field_type="email",
                    required=True,
                    label="Email",
                    placeholder="you@example.com",
                ),
                FieldHint(
                    name="password",
                    field_type="password",
                    required=True,
                    label="Password",
                ),
                FieldHint(
                    name="password_confirm",
                    field_type="password",
                    required=True,
                    label="Confirm password",
                ),
            ],
        )

    def _resolve_user_model(self, context: StepContext) -> Any:
        model_path = context.config.user_model
        app_label, model_name = model_path.rsplit(".", 1)
        return Tortoise.apps[app_label][model_name]
