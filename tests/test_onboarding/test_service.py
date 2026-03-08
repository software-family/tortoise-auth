"""Tests for OnboardingService — integration tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from tortoise.timezone import now as tz_now

from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    OnboardingFlowCompleteError,
    OnboardingSessionExpiredError,
    OnboardingSessionInvalidError,
)
from tortoise_auth.models.onboarding import OnboardingSession, hash_session_token
from tortoise_auth.onboarding.service import OnboardingService
from tortoise_auth.onboarding.steps.register import RegisterStep
from tortoise_auth.onboarding.steps.verify_email import VerifyEmailStep


@pytest.fixture()
def config() -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        signing_secret="test-secret-key",
        jwt_secret="test-jwt-secret",
        password_validators=[],
        onboarding_session_lifetime=3600,
        onboarding_verification_code_ttl=600,
        onboarding_max_verification_attempts=3,
    )


@pytest.fixture()
def service(config: AuthConfig) -> OnboardingService:
    steps = {
        "register": RegisterStep(),
        "verify_email": VerifyEmailStep(),
    }
    return OnboardingService(
        config,
        steps=steps,
        pipeline=["register", "verify_email"],
    )


@pytest.fixture(autouse=True)
def clear_events():
    emitter.clear()
    yield
    emitter.clear()


class TestStart:
    async def test_creates_session(self, service: OnboardingService) -> None:
        result = await service.start("user@example.com")
        assert result.status == "in_progress"
        assert result.current_step == "register"
        assert result.session_token != ""
        assert result.client_hint is not None
        assert result.client_hint.step_name == "register"
        assert result.auth_result is None

    async def test_session_persisted(self, service: OnboardingService) -> None:
        result = await service.start("user@example.com")
        token_hash = hash_session_token(result.session_token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        assert session is not None
        assert session.email == "user@example.com"

    async def test_emits_started_event(self, service: OnboardingService) -> None:
        events: list[dict] = []

        @emitter.on("onboarding_started")
        async def handler(**kwargs):
            events.append(kwargs)

        await service.start("user@example.com")
        assert len(events) == 1
        assert events[0]["email"] == "user@example.com"

    async def test_invalidates_previous_sessions(self, service: OnboardingService) -> None:
        result1 = await service.start("user@example.com")
        result2 = await service.start("user@example.com")

        hash1 = hash_session_token(result1.session_token)
        session1 = await OnboardingSession.filter(token_hash=hash1).first()
        assert session1 is not None
        assert session1.is_invalidated is True

        hash2 = hash_session_token(result2.session_token)
        session2 = await OnboardingSession.filter(token_hash=hash2).first()
        assert session2 is not None
        assert session2.is_invalidated is False

    async def test_remaining_and_completed_steps(self, service: OnboardingService) -> None:
        result = await service.start("user@example.com")
        assert result.completed_steps == []
        assert "register" in result.remaining_steps
        assert "verify_email" in result.remaining_steps


class TestAdvance:
    async def test_register_step(self, service: OnboardingService) -> None:
        start = await service.start("user@example.com")
        result = await service.advance(
            start.session_token,
            {
                "email": "user@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        assert result.status == "in_progress"
        assert result.current_step == "verify_email"
        assert result.step_result is not None
        assert result.step_result.success is True
        assert "register" in result.completed_steps

    async def test_register_then_verify_email(self, service: OnboardingService) -> None:
        codes: list[str] = []

        @emitter.on("verification_code_generated")
        async def capture_code(**kwargs):
            codes.append(kwargs["code"])

        start = await service.start("flow@example.com")
        # Step 1: register
        r1 = await service.advance(
            start.session_token,
            {
                "email": "flow@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        assert r1.current_step == "verify_email"

        # Step 2: send verification code (empty data triggers code generation)
        r2 = await service.advance(start.session_token, {})
        assert r2.status == "in_progress"
        assert r2.current_step == "verify_email"
        assert len(codes) == 1

        # Step 3: verify the code
        r3 = await service.advance(start.session_token, {"code": codes[0]})
        assert r3.status == "completed"
        assert r3.auth_result is not None
        assert r3.auth_result.access_token != ""
        assert r3.auth_result.refresh_token != ""

    async def test_step_failure_returns_error(self, service: OnboardingService) -> None:
        start = await service.start("user@example.com")
        result = await service.advance(
            start.session_token,
            {"email": "", "password": "", "password_confirm": ""},
        )
        assert result.status == "error"
        assert result.step_result is not None
        assert result.step_result.success is False
        assert len(result.step_result.errors) > 0
        # Should return client_hint for retry
        assert result.client_hint is not None

    async def test_completed_flow_raises(self, service: OnboardingService) -> None:
        codes: list[str] = []

        @emitter.on("verification_code_generated")
        async def capture_code(**kwargs):
            codes.append(kwargs["code"])

        start = await service.start("done@example.com")
        await service.advance(
            start.session_token,
            {
                "email": "done@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        await service.advance(start.session_token, {})
        await service.advance(start.session_token, {"code": codes[0]})

        with pytest.raises(OnboardingFlowCompleteError):
            await service.advance(start.session_token, {})

    async def test_emits_step_completed_event(self, service: OnboardingService) -> None:
        events: list[dict] = []

        @emitter.on("onboarding_step_completed")
        async def handler(**kwargs):
            events.append(kwargs)

        start = await service.start("event@example.com")
        await service.advance(
            start.session_token,
            {
                "email": "event@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        assert len(events) == 1
        assert events[0]["step_name"] == "register"

    async def test_emits_step_failed_event(self, service: OnboardingService) -> None:
        events: list[dict] = []

        @emitter.on("onboarding_step_failed")
        async def handler(**kwargs):
            events.append(kwargs)

        start = await service.start("fail@example.com")
        await service.advance(start.session_token, {})
        # Registration fails with empty data — but the register step validates email/password
        # Actually register step with empty data fails
        assert len(events) == 1
        assert events[0]["step_name"] == "register"


class TestSkip:
    async def test_skip_non_skippable_returns_error(self, service: OnboardingService) -> None:
        start = await service.start("user@example.com")
        result = await service.advance(start.session_token, {}, skip=True)
        assert result.status == "error"
        assert "cannot be skipped" in result.step_result.errors[0]


class TestResume:
    async def test_resume_returns_current_step(self, service: OnboardingService) -> None:
        start = await service.start("resume@example.com")
        result = await service.resume(start.session_token)
        assert result.status == "in_progress"
        assert result.current_step == "register"
        assert result.client_hint is not None
        assert result.step_result is None

    async def test_resume_after_advance(self, service: OnboardingService) -> None:
        start = await service.start("resume2@example.com")
        await service.advance(
            start.session_token,
            {
                "email": "resume2@example.com",
                "password": "StrongP@ss1",
                "password_confirm": "StrongP@ss1",
            },
        )
        result = await service.resume(start.session_token)
        assert result.current_step == "verify_email"


class TestExpiredSession:
    async def test_expired_session_raises(self, service: OnboardingService) -> None:
        start = await service.start("expired@example.com")
        # Manually expire the session
        token_hash = hash_session_token(start.session_token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        session.expires_at = tz_now() - timedelta(seconds=1)
        await session.save(update_fields=["expires_at"])

        with pytest.raises(OnboardingSessionExpiredError):
            await service.advance(start.session_token, {})

    async def test_expired_session_on_resume(self, service: OnboardingService) -> None:
        start = await service.start("expired2@example.com")
        token_hash = hash_session_token(start.session_token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        session.expires_at = tz_now() - timedelta(seconds=1)
        await session.save(update_fields=["expires_at"])

        with pytest.raises(OnboardingSessionExpiredError):
            await service.resume(start.session_token)


class TestInvalidSession:
    async def test_unknown_token_raises(self, service: OnboardingService) -> None:
        with pytest.raises(OnboardingSessionInvalidError):
            await service.advance("nonexistent-token", {})

    async def test_invalidated_session_raises(self, service: OnboardingService) -> None:
        start = await service.start("invalid@example.com")
        token_hash = hash_session_token(start.session_token)
        session = await OnboardingSession.filter(token_hash=token_hash).first()
        session.is_invalidated = True
        await session.save(update_fields=["is_invalidated"])

        with pytest.raises(OnboardingSessionInvalidError):
            await service.advance(start.session_token, {})


class TestCleanupExpired:
    async def test_cleanup_removes_expired(self, service: OnboardingService) -> None:
        await OnboardingSession.create(
            token_hash=hash_session_token("old-tok"),
            email="old@example.com",
            pipeline="[]",
            expires_at=tz_now() - timedelta(hours=1),
        )
        await OnboardingSession.create(
            token_hash=hash_session_token("new-tok"),
            email="new@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
        )
        deleted = await service.cleanup_expired()
        assert deleted == 1
        assert await OnboardingSession.filter(email="new@example.com").exists()

    async def test_cleanup_keeps_active(self, service: OnboardingService) -> None:
        await OnboardingSession.create(
            token_hash=hash_session_token("active-tok"),
            email="active@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
        )
        deleted = await service.cleanup_expired()
        assert deleted == 0
