"""Tests for the VerifyEmailStep."""

from __future__ import annotations

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.onboarding import OnboardingStep, StepContext
from tortoise_auth.onboarding.steps.verify_email import VerifyEmailStep
from tortoise_auth.signing import TimestampSigner


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        signing_secret="test-secret-key-for-signing",
        onboarding_verification_code_ttl=600,
        onboarding_max_verification_attempts=3,
    )


@pytest.fixture()
def step() -> VerifyEmailStep:
    return VerifyEmailStep()


@pytest.fixture(autouse=True)
def clear_events():
    emitter.clear()
    yield
    emitter.clear()


class TestVerifyEmailProtocol:
    def test_implements_protocol(self, step: VerifyEmailStep) -> None:
        assert isinstance(step, OnboardingStep)

    def test_name(self, step: VerifyEmailStep) -> None:
        assert step.name == "verify_email"

    def test_not_skippable(self, step: VerifyEmailStep) -> None:
        assert step.skippable is False

    async def test_required_when_not_verified(
        self, step: VerifyEmailStep, config: AuthConfig
    ) -> None:
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        assert await step.is_required(context) is True

    async def test_not_required_when_verified(
        self, step: VerifyEmailStep, config: AuthConfig
    ) -> None:
        context = StepContext(
            session_id="s1",
            step_data={"email_verified": True},
            user_id=None,
            config=config,
        )
        assert await step.is_required(context) is False


class TestVerifyEmailClientHint:
    def test_hint_before_code_sent(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        context = StepContext(session_id="s1", step_data={}, user_id=None, config=config)
        hint = step.client_hint(context)
        assert hint.step_name == "verify_email"
        assert hint.extra.get("action") == "send_code"

    def test_hint_after_code_sent(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        context = StepContext(
            session_id="s1",
            step_data={"_verification_code_signed": "signed-value"},
            user_id=None,
            config=config,
        )
        hint = step.client_hint(context)
        assert len(hint.fields) == 1
        assert hint.fields[0].name == "code"


class TestVerifyEmailSendCode:
    async def test_send_code_emits_event(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        events: list[dict] = []

        @emitter.on("verification_code_generated")
        async def handler(**kwargs):
            events.append(kwargs)

        context = StepContext(
            session_id="s1",
            step_data={"email": "user@example.com"},
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {})
        assert result.success is True
        assert "_verification_code_signed" in result.data
        assert result.data["_verification_attempts"] == 0
        assert len(events) == 1
        assert events[0]["email"] == "user@example.com"
        assert len(events[0]["code"]) == 6

    async def test_send_code_returns_signed_value(
        self, step: VerifyEmailStep, config: AuthConfig
    ) -> None:
        context = StepContext(
            session_id="s1",
            step_data={"email": "user@example.com"},
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {})
        signed = result.data["_verification_code_signed"]
        # Should be unsignable
        signer = TimestampSigner(config.effective_signing_secret)
        code = signer.unsign_with_timestamp(signed, max_age=600)
        assert len(code) == 6
        assert code.isdigit()


class TestVerifyEmailVerifyCode:
    async def test_correct_code(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        # Phase 1: send code
        context1 = StepContext(
            session_id="s1",
            step_data={"email": "user@example.com"},
            user_id=None,
            config=config,
        )
        send_result = await step.execute(context1, {})
        signed = send_result.data["_verification_code_signed"]

        # Extract the original code
        signer = TimestampSigner(config.effective_signing_secret)
        code = signer.unsign_with_timestamp(signed, max_age=600)

        # Phase 2: verify code
        context2 = StepContext(
            session_id="s1",
            step_data={
                "email": "user@example.com",
                "_verification_code_signed": signed,
                "_verification_attempts": 0,
            },
            user_id=None,
            config=config,
        )
        result = await step.execute(context2, {"code": code})
        assert result.success is True
        assert result.data.get("email_verified") is True

    async def test_wrong_code(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        signer = TimestampSigner(config.effective_signing_secret)
        signed = signer.sign_with_timestamp("123456")

        context = StepContext(
            session_id="s1",
            step_data={
                "_verification_code_signed": signed,
                "_verification_attempts": 0,
            },
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {"code": "000000"})
        assert result.success is False
        assert any("Invalid" in e for e in result.errors)
        assert result.data["_verification_attempts"] == 1

    async def test_no_code_sent_yet(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        context = StepContext(
            session_id="s1",
            step_data={},
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {"code": "123456"})
        assert result.success is False
        assert any("No verification code" in e for e in result.errors)

    async def test_max_attempts_exceeded(self, step: VerifyEmailStep, config: AuthConfig) -> None:
        signer = TimestampSigner(config.effective_signing_secret)
        signed = signer.sign_with_timestamp("123456")

        context = StepContext(
            session_id="s1",
            step_data={
                "_verification_code_signed": signed,
                "_verification_attempts": 3,  # Already at max
            },
            user_id=None,
            config=config,
        )
        result = await step.execute(context, {"code": "000000"})
        assert result.success is False
        assert any("Maximum" in e for e in result.errors)
        assert result.data.get("_max_attempts_exceeded") is True
