"""Tests for the ValidateInvitationStep."""

from __future__ import annotations

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.onboarding import OnboardingStep, StepContext
from tortoise_auth.onboarding.steps.validate_invitation import ValidateInvitationStep
from tortoise_auth.services.invitation import InvitationService


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        signing_secret="test-signing-secret-that-is-at-least-32-bytes!",
        jwt_secret="test-jwt-secret-key-that-is-at-least-32-bytes!",
        invitation_require=True,
        **overrides,
    )


@pytest.fixture(autouse=True)
def _clear_events():
    emitter.clear()
    yield
    emitter.clear()


@pytest.fixture(autouse=True)
def _clear_config():
    from tortoise_auth import config as cfg_mod

    cfg_mod._config = None
    yield
    cfg_mod._config = None


@pytest.fixture()
def config() -> AuthConfig:
    return make_config()


@pytest.fixture()
def context(config: AuthConfig) -> StepContext:
    return StepContext(session_id="sess-1", step_data={}, user_id=None, config=config)


@pytest.fixture()
def step() -> ValidateInvitationStep:
    return ValidateInvitationStep()


class TestProtocol:
    def test_implements_protocol(self, step: ValidateInvitationStep) -> None:
        assert isinstance(step, OnboardingStep)

    def test_name(self, step: ValidateInvitationStep) -> None:
        assert step.name == "validate_invitation"

    def test_not_skippable(self, step: ValidateInvitationStep) -> None:
        assert step.skippable is False


class TestIsRequired:
    async def test_required_when_invitation_require_true(
        self, step: ValidateInvitationStep, context: StepContext
    ) -> None:
        assert await step.is_required(context) is True

    async def test_not_required_when_invitation_require_false(
        self, step: ValidateInvitationStep
    ) -> None:
        cfg = AuthConfig(
            user_model="models.MinimalUser",
            signing_secret="test-signing-secret-that-is-at-least-32-bytes!",
            invitation_require=False,
        )
        ctx = StepContext(session_id="sess-1", step_data={}, user_id=None, config=cfg)
        assert await step.is_required(ctx) is False


class TestClientHint:
    def test_hint_fields(self, step: ValidateInvitationStep, context: StepContext) -> None:
        hint = step.client_hint(context)
        assert hint.step_name == "validate_invitation"
        field_names = [f.name for f in hint.fields]
        assert "invitation_token" in field_names


class TestExecute:
    async def test_missing_token_fails(
        self, step: ValidateInvitationStep, context: StepContext
    ) -> None:
        result = await step.execute(context, {})
        assert result.success is False
        assert any("required" in e.lower() for e in result.errors)

    async def test_empty_token_fails(
        self, step: ValidateInvitationStep, context: StepContext
    ) -> None:
        result = await step.execute(context, {"invitation_token": "  "})
        assert result.success is False

    async def test_invalid_token_fails(
        self, step: ValidateInvitationStep, context: StepContext
    ) -> None:
        result = await step.execute(context, {"invitation_token": "bad-token"})
        assert result.success is False

    async def test_valid_token_succeeds(
        self, step: ValidateInvitationStep, context: StepContext
    ) -> None:
        svc = InvitationService(context.config)
        token = await svc.create_invitation(
            "admin@example.com", invited_by="1", role="editor"
        )

        result = await step.execute(context, {"invitation_token": token})
        assert result.success is True
        assert result.data["email"] == "admin@example.com"
        assert result.data["invitation_token"] == token
        assert result.data["invited_by"] == "1"
        assert result.data["invitation_role"] == "editor"