"""Tests for the ProfileCompletionStep."""

from __future__ import annotations

import pytest
from tortoise import Tortoise

from tortoise_auth.config import AuthConfig
from tortoise_auth.onboarding import OnboardingStep, StepContext
from tortoise_auth.onboarding.steps.profile import ProfileCompletionStep


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(user_model="models.FullUser")


class TestProfileProtocol:
    def test_implements_protocol(self) -> None:
        assert isinstance(ProfileCompletionStep(), OnboardingStep)

    def test_name(self) -> None:
        assert ProfileCompletionStep().name == "profile"

    def test_skippable_no_required(self) -> None:
        assert ProfileCompletionStep().skippable is True

    def test_not_skippable_with_required(self) -> None:
        step = ProfileCompletionStep(required_fields=["phone"])
        assert step.skippable is False


class TestProfileRequired:
    async def test_required_when_fields_configured(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep(required_fields=["phone"])
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        assert await step.is_required(context) is True

    async def test_required_when_optional_fields(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep(optional_fields=["phone"])
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        assert await step.is_required(context) is True

    async def test_not_required_when_no_fields(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep()
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        assert await step.is_required(context) is False


class TestProfileClientHint:
    def test_hint_with_required_and_optional(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep(required_fields=["phone"], optional_fields=["bio"])
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        hint = step.client_hint(context)
        assert hint.step_name == "profile"
        assert len(hint.fields) == 2
        assert hint.fields[0].name == "phone"
        assert hint.fields[0].required is True
        assert hint.fields[1].name == "bio"
        assert hint.fields[1].required is False


class TestProfileExecute:
    async def test_missing_required_field(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep(required_fields=["phone"])
        user_model = Tortoise.apps["models"]["FullUser"]
        user = await user_model.create(email="profile@example.com", phone="")
        await user.set_password("StrongP@ss1")

        context = StepContext(session_id="s1", step_data={}, user_id=str(user.pk), config=config)
        result = await step.execute(context, {})
        assert result.success is False
        assert any("phone" in e for e in result.errors)

    async def test_update_profile(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep(required_fields=["phone"])
        user_model = Tortoise.apps["models"]["FullUser"]
        user = await user_model.create(email="profile2@example.com", phone="")
        await user.set_password("StrongP@ss1")

        context = StepContext(session_id="s1", step_data={}, user_id=str(user.pk), config=config)
        result = await step.execute(context, {"phone": "1234567890"})
        assert result.success is True

        await user.refresh_from_db()
        assert user.phone == "1234567890"

    async def test_no_user_id(self, config: AuthConfig) -> None:
        step = ProfileCompletionStep(required_fields=["phone"])
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        result = await step.execute(context, {"phone": "123"})
        assert result.success is False
        assert any("No user" in e for e in result.errors)
