"""Tests for the SetupTOTPStep."""

from __future__ import annotations

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.onboarding import OnboardingStep, StepContext
from tortoise_auth.onboarding.steps.setup_totp import SetupTOTPStep


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(user_model="models.MinimalUser", onboarding_require_totp=True)


@pytest.fixture()
def step() -> SetupTOTPStep:
    return SetupTOTPStep()


class TestSetupTOTPProtocol:
    def test_implements_protocol(self, step: SetupTOTPStep) -> None:
        assert isinstance(step, OnboardingStep)

    def test_name(self, step: SetupTOTPStep) -> None:
        assert step.name == "setup_totp"

    def test_skippable(self, step: SetupTOTPStep) -> None:
        assert step.skippable is True


class TestSetupTOTPRequired:
    async def test_required_when_config_enabled(
        self, step: SetupTOTPStep, config: AuthConfig
    ) -> None:
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        assert await step.is_required(context) is True

    async def test_not_required_when_config_disabled(self, step: SetupTOTPStep) -> None:
        config = AuthConfig(user_model="models.MinimalUser", onboarding_require_totp=False)
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        assert await step.is_required(context) is False


class TestSetupTOTPClientHint:
    def test_hint_before_secret(self, step: SetupTOTPStep, config: AuthConfig) -> None:
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        hint = step.client_hint(context)
        assert hint.extra.get("action") == "generate_secret"
        assert hint.skippable is True

    def test_hint_after_secret(self, step: SetupTOTPStep, config: AuthConfig) -> None:
        context = StepContext(
            session_id="s1",
            step_data={
                "_totp_secret": "JBSWY3DPEHPK3PXP",
                "_totp_provisioning_uri": "otpauth://...",
            },
            user_id=None,
            config=config,
        )
        hint = step.client_hint(context)
        assert len(hint.fields) == 1
        assert hint.fields[0].name == "code"
        assert hint.extra.get("secret") == "JBSWY3DPEHPK3PXP"


class TestSetupTOTPExecute:
    async def test_generate_secret(self, step: SetupTOTPStep, config: AuthConfig) -> None:
        context = StepContext(
            session_id="s1",
            step_data={"email": "user@example.com"},
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {})
        assert result.success is True
        assert "_totp_secret" in result.data
        assert "_totp_provisioning_uri" in result.data
        assert "otpauth://" in result.data["_totp_provisioning_uri"]

    async def test_verify_correct_code(self, step: SetupTOTPStep, config: AuthConfig) -> None:
        import pyotp

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()

        context = StepContext(
            session_id="s1",
            step_data={"_totp_secret": secret},
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {"code": code})
        assert result.success is True
        assert result.data.get("totp_enabled") is True

    async def test_verify_wrong_code(self, step: SetupTOTPStep, config: AuthConfig) -> None:
        context = StepContext(
            session_id="s1",
            step_data={"_totp_secret": "JBSWY3DPEHPK3PXP"},
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {"code": "000000"})
        assert result.success is False
        assert any("Invalid" in e for e in result.errors)

    async def test_no_secret_generated(self, step: SetupTOTPStep, config: AuthConfig) -> None:
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        result = await step.execute(context, {"code": "123456"})
        assert result.success is False
        assert any("No TOTP secret" in e for e in result.errors)
