"""Tests for the RegisterStep."""

from __future__ import annotations

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.onboarding import OnboardingStep, StepContext
from tortoise_auth.onboarding.steps.register import RegisterStep


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(user_model="models.MinimalUser", password_validators=[])


@pytest.fixture()
def context(config: AuthConfig) -> StepContext:
    return StepContext(session_id="sess-1", step_data={}, user_id=None, config=config)


@pytest.fixture()
def step() -> RegisterStep:
    return RegisterStep()


class TestRegisterStepProtocol:
    def test_implements_protocol(self, step: RegisterStep) -> None:
        assert isinstance(step, OnboardingStep)

    def test_name(self, step: RegisterStep) -> None:
        assert step.name == "register"

    def test_not_skippable(self, step: RegisterStep) -> None:
        assert step.skippable is False

    async def test_always_required(self, step: RegisterStep, context: StepContext) -> None:
        assert await step.is_required(context) is True


class TestRegisterStepClientHint:
    def test_hint_fields(self, step: RegisterStep, context: StepContext) -> None:
        hint = step.client_hint(context)
        assert hint.step_name == "register"
        field_names = [f.name for f in hint.fields]
        assert "email" in field_names
        assert "password" in field_names
        assert "password_confirm" in field_names


class TestRegisterStepExecute:
    async def test_missing_email(self, step: RegisterStep, context: StepContext) -> None:
        result = await step.execute(context, {"password": "abc", "password_confirm": "abc"})
        assert result.success is False
        assert any("Email" in e for e in result.errors)

    async def test_invalid_email(self, step: RegisterStep, context: StepContext) -> None:
        result = await step.execute(
            context, {"email": "notanemail", "password": "abc", "password_confirm": "abc"}
        )
        assert result.success is False
        assert any("email" in e.lower() for e in result.errors)

    async def test_missing_password(self, step: RegisterStep, context: StepContext) -> None:
        result = await step.execute(context, {"email": "a@b.com"})
        assert result.success is False
        assert any("Password" in e for e in result.errors)

    async def test_password_mismatch(self, step: RegisterStep, context: StepContext) -> None:
        result = await step.execute(
            context,
            {"email": "a@b.com", "password": "abc123", "password_confirm": "xyz456"},
        )
        assert result.success is False
        assert any("match" in e.lower() for e in result.errors)

    async def test_successful_registration(self, step: RegisterStep, context: StepContext) -> None:
        result = await step.execute(
            context,
            {
                "email": "new@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        assert result.success is True
        assert "user_id" in result.data

    async def test_duplicate_email(self, step: RegisterStep, context: StepContext) -> None:
        await step.execute(
            context,
            {
                "email": "dup@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        result = await step.execute(
            context,
            {
                "email": "dup@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        assert result.success is False
        assert any("taken" in e.lower() for e in result.errors)
