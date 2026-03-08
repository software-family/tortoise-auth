"""Tests for the OnboardingSession model."""

from datetime import timedelta

from tortoise.timezone import now as tz_now

from tortoise_auth.models.onboarding import (
    OnboardingSession,
    generate_session_token,
    hash_session_token,
)


class TestHashSessionToken:
    def test_deterministic(self) -> None:
        assert hash_session_token("abc") == hash_session_token("abc")

    def test_different_inputs(self) -> None:
        assert hash_session_token("abc") != hash_session_token("xyz")

    def test_returns_hex_string(self) -> None:
        result = hash_session_token("test")
        assert len(result) == 64
        int(result, 16)  # should not raise


class TestGenerateSessionToken:
    def test_length(self) -> None:
        token = generate_session_token(64)
        assert len(token) == 64

    def test_uniqueness(self) -> None:
        tokens = {generate_session_token(64) for _ in range(10)}
        assert len(tokens) == 10


class TestOnboardingSessionModel:
    async def test_create_session(self) -> None:
        token = generate_session_token(64)
        session = await OnboardingSession.create(
            token_hash=hash_session_token(token),
            email="user@example.com",
            pipeline='["register"]',
            expires_at=tz_now() + timedelta(hours=1),
        )
        assert session.id is not None
        assert session.email == "user@example.com"
        assert session.is_invalidated is False
        assert session.completed_at is None

    async def test_is_valid_active_session(self) -> None:
        session = await OnboardingSession.create(
            token_hash=hash_session_token("tok1"),
            email="user@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
        )
        assert session.is_valid is True

    async def test_is_expired(self) -> None:
        session = await OnboardingSession.create(
            token_hash=hash_session_token("tok2"),
            email="user@example.com",
            pipeline="[]",
            expires_at=tz_now() - timedelta(seconds=1),
        )
        assert session.is_expired is True
        assert session.is_valid is False

    async def test_is_invalidated(self) -> None:
        session = await OnboardingSession.create(
            token_hash=hash_session_token("tok3"),
            email="user@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
            is_invalidated=True,
        )
        assert session.is_valid is False

    async def test_completed_session_is_not_valid(self) -> None:
        session = await OnboardingSession.create(
            token_hash=hash_session_token("tok4"),
            email="user@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
            completed_at=tz_now(),
        )
        assert session.is_valid is False

    async def test_repr(self) -> None:
        session = await OnboardingSession.create(
            token_hash=hash_session_token("tok5"),
            email="user@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
        )
        assert "OnboardingSession" in repr(session)
        assert "user@example.com" in repr(session)

    async def test_lookup_by_token_hash(self) -> None:
        raw = generate_session_token(64)
        hashed = hash_session_token(raw)
        await OnboardingSession.create(
            token_hash=hashed,
            email="lookup@example.com",
            pipeline="[]",
            expires_at=tz_now() + timedelta(hours=1),
        )
        found = await OnboardingSession.filter(token_hash=hashed).first()
        assert found is not None
        assert found.email == "lookup@example.com"
