"""ProfileCompletionStep — collect additional user profile fields."""

from __future__ import annotations

from typing import Any

from tortoise import Tortoise

from tortoise_auth.onboarding import ClientHint, FieldHint, StepContext, StepResult


class ProfileCompletionStep:
    """Onboarding step for collecting additional profile information.

    Configurable via required_fields and optional_fields at construction time.
    """

    def __init__(
        self,
        required_fields: list[str] | None = None,
        optional_fields: list[str] | None = None,
    ) -> None:
        self._required_fields = required_fields or []
        self._optional_fields = optional_fields or []

    @property
    def name(self) -> str:
        return "profile"

    @property
    def skippable(self) -> bool:
        return len(self._required_fields) == 0

    async def is_required(self, context: StepContext) -> bool:
        return bool(self._required_fields or self._optional_fields)

    async def execute(self, context: StepContext, data: dict[str, Any]) -> StepResult:
        errors: list[str] = []

        # Validate required fields
        for field_name in self._required_fields:
            value = data.get(field_name, "")
            if isinstance(value, str):
                value = value.strip()
            if not value:
                errors.append(f"{field_name} is required")

        if errors:
            return StepResult(success=False, errors=errors)

        # Update user model
        user_id = context.user_id
        if not user_id:
            return StepResult(success=False, errors=["No user found in session"])

        user_model = self._resolve_user_model(context)
        user = await user_model.filter(pk=user_id).first()
        if not user:
            return StepResult(success=False, errors=["User not found"])

        update_fields: list[str] = []
        all_fields = self._required_fields + self._optional_fields
        for field_name in all_fields:
            value = data.get(field_name)
            if value is not None and hasattr(user, field_name):
                if isinstance(value, str):
                    value = value.strip()
                setattr(user, field_name, value)
                update_fields.append(field_name)

        if update_fields:
            await user.save(update_fields=update_fields)

        profile_data = {f: data.get(f, "") for f in all_fields if data.get(f) is not None}
        return StepResult(success=True, data=profile_data)

    def client_hint(self, context: StepContext) -> ClientHint:
        fields: list[FieldHint] = []

        for field_name in self._required_fields:
            fields.append(
                FieldHint(
                    name=field_name,
                    field_type="text",
                    required=True,
                    label=field_name.replace("_", " ").title(),
                )
            )

        for field_name in self._optional_fields:
            fields.append(
                FieldHint(
                    name=field_name,
                    field_type="text",
                    required=False,
                    label=field_name.replace("_", " ").title(),
                )
            )

        return ClientHint(
            step_name=self.name,
            title="Complete your profile",
            description="Tell us a bit more about yourself.",
            skippable=self.skippable,
            fields=fields,
        )

    def _resolve_user_model(self, context: StepContext) -> Any:
        model_path = context.config.user_model
        app_label, model_name = model_path.rsplit(".", 1)
        return Tortoise.apps[app_label][model_name]
