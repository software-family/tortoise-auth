"""Tests for the PasswordResetService."""

import pytest

from tests.models import MinimalUser
from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    BadSignatureError,
    ConfigurationError,
    InvalidPasswordError,
    PasswordResetError,
    RateLimitError,
    SignatureExpiredError,
)
from tortoise_auth.rate_limit.memory import InMemoryRateLimitBackend
from tortoise_auth.services.password import PasswordResetService
from tortoise_auth.signing import verify_token
from tortoise_auth.tokens.jwt import JWTBackend


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        signing_secret="test-signing-secret-that-is-at-least-32-bytes!",
        jwt_secret="test-jwt-secret-key-that-is-at-least-32-bytes!",
        jwt_blacklist_enabled=True,
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


async def _create_user(
    email: str = "user@example.com", password: str = "Str0ngP@ss!"
) -> MinimalUser:
    user = await MinimalUser.create(email=email)
    await user.set_password(password)
    return user


class TestPasswordResetRequest:
    async def test_emits_event_for_existing_user(self):
        user = await _create_user()
        cfg = make_config()
        svc = PasswordResetService(cfg)
        events: list[dict[str, object]] = []

        @emitter.on("password_reset_requested")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.request_reset("user@example.com")

        assert len(events) == 1
        assert events[0]["email"] == "user@example.com"
        assert events[0]["user"] == user
        assert isinstance(events[0]["token"], str)

    async def test_silent_for_nonexistent_email(self):
        cfg = make_config()
        svc = PasswordResetService(cfg)
        events: list[dict[str, object]] = []

        @emitter.on("password_reset_requested")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.request_reset("nobody@example.com")

        assert len(events) == 0

    async def test_silent_for_inactive_user(self):
        user = await _create_user()
        user.is_active = False
        await user.save(update_fields=["is_active"])
        cfg = make_config()
        svc = PasswordResetService(cfg)
        events: list[dict[str, object]] = []

        @emitter.on("password_reset_requested")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.request_reset("user@example.com")

        assert len(events) == 0

    async def test_rate_limited_after_max_attempts(self):
        await _create_user()
        cfg = make_config(
            password_reset_rate_limit_max_attempts=2,
            password_reset_rate_limit_window=300,
            rate_limit_max_attempts=2,
            rate_limit_window=300,
            rate_limit_lockout=600,
        )
        limiter = InMemoryRateLimitBackend(cfg)
        svc = PasswordResetService(cfg, rate_limiter=limiter)

        # Use up attempts
        for _ in range(2):
            await svc.request_reset("user@example.com")

        with pytest.raises(RateLimitError):
            await svc.request_reset("user@example.com")

    async def test_records_attempts_for_nonexistent_emails(self):
        cfg = make_config(
            rate_limit_max_attempts=2,
            rate_limit_window=300,
            rate_limit_lockout=600,
        )
        limiter = InMemoryRateLimitBackend(cfg)
        svc = PasswordResetService(cfg, rate_limiter=limiter)

        for _ in range(2):
            await svc.request_reset("nobody@example.com")

        with pytest.raises(RateLimitError):
            await svc.request_reset("nobody@example.com")

    async def test_rate_limit_emits_event(self):
        cfg = make_config(
            rate_limit_max_attempts=1,
            rate_limit_window=300,
            rate_limit_lockout=600,
        )
        limiter = InMemoryRateLimitBackend(cfg)
        svc = PasswordResetService(cfg, rate_limiter=limiter)
        events: list[dict[str, object]] = []

        @emitter.on("rate_limit_exceeded")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.request_reset("user@example.com")

        with pytest.raises(RateLimitError):
            await svc.request_reset("user@example.com")

        assert len(events) == 1
        assert events[0]["identifier"] == "user@example.com"

    async def test_token_contains_user_pk(self):
        user = await _create_user()
        cfg = make_config()
        svc = PasswordResetService(cfg)
        events: list[dict[str, object]] = []

        @emitter.on("password_reset_requested")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.request_reset("user@example.com")

        token = events[0]["token"]
        assert isinstance(token, str)
        decoded_pk = verify_token(token, secret=cfg.effective_signing_secret)
        assert decoded_pk == str(user.pk)


class TestPasswordResetConfirm:
    async def _request_token(self, cfg: AuthConfig, email: str = "user@example.com") -> str:
        """Helper to request a reset and capture the token from the event."""
        svc = PasswordResetService(cfg)
        tokens: list[str] = []

        @emitter.on("password_reset_requested")
        async def handler(**kwargs: object) -> None:
            tokens.append(kwargs["token"])  # type: ignore[arg-type]

        await svc.request_reset(email)
        emitter.remove_listener("password_reset_requested", handler)
        return tokens[0]

    async def test_success_password_changed(self):
        from tortoise_auth.services.auth import AuthService

        await _create_user()
        cfg = make_config()
        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg)

        await svc.confirm_reset(token, "N3wStr0ngP@ss!")

        # Verify new password works
        auth_svc = AuthService(cfg)
        result = await auth_svc.login("user@example.com", "N3wStr0ngP@ss!")
        assert result.user.email == "user@example.com"

    async def test_expired_token_raises(self):
        await _create_user()
        cfg = make_config(password_reset_token_lifetime=1)
        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg)

        import time

        time.sleep(2)

        with pytest.raises(SignatureExpiredError):
            await svc.confirm_reset(token, "N3wStr0ngP@ss!")

    async def test_invalid_token_raises(self):
        cfg = make_config()
        svc = PasswordResetService(cfg)

        with pytest.raises(BadSignatureError):
            await svc.confirm_reset("invalid-token", "N3wStr0ngP@ss!")

    async def test_nonexistent_user_raises(self):
        from tortoise_auth.signing import make_token

        cfg = make_config()
        svc = PasswordResetService(cfg)
        # Create a valid token for a non-existent user PK
        token = make_token("99999", cfg.effective_signing_secret)

        with pytest.raises(PasswordResetError, match="User not found"):
            await svc.confirm_reset(token, "N3wStr0ngP@ss!")

    async def test_inactive_user_raises(self):
        user = await _create_user()
        cfg = make_config()
        token = await self._request_token(cfg)

        user.is_active = False
        await user.save(update_fields=["is_active"])

        svc = PasswordResetService(cfg)

        with pytest.raises(PasswordResetError, match="inactive"):
            await svc.confirm_reset(token, "N3wStr0ngP@ss!")

    async def test_weak_password_raises(self):
        await _create_user()
        cfg = make_config()
        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg)

        with pytest.raises(InvalidPasswordError):
            await svc.confirm_reset(token, "123")

    async def test_emits_password_reset_completed_event(self):
        await _create_user()
        cfg = make_config()
        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg)
        events: list[dict[str, object]] = []

        @emitter.on("password_reset_completed")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.confirm_reset(token, "N3wStr0ngP@ss!")

        assert len(events) == 1
        assert events[0]["user"] is not None

    async def test_emits_password_changed_event(self):
        await _create_user()
        cfg = make_config()
        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg)
        events: list[object] = []

        @emitter.on("password_changed")
        async def handler(*args: object, **kwargs: object) -> None:
            events.append(True)

        await svc.confirm_reset(token, "N3wStr0ngP@ss!")

        assert len(events) == 1

    async def test_invalidates_sessions_with_token_backend(self):
        user = await _create_user()
        cfg = make_config()
        backend = JWTBackend(cfg)
        # Create a session token first
        tokens = await backend.create_tokens(str(user.pk))
        # Verify the token is valid
        await backend.verify_token(tokens.access_token)

        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg, token_backend=backend)

        await svc.confirm_reset(token, "N3wStr0ngP@ss!")

        # Old session should be revoked
        from tortoise_auth.exceptions import TokenRevokedError

        with pytest.raises(TokenRevokedError):
            await backend.verify_token(tokens.access_token)

    async def test_works_without_token_backend(self):
        await _create_user()
        cfg = make_config()
        token = await self._request_token(cfg)
        svc = PasswordResetService(cfg)  # No token_backend

        # Should not raise
        await svc.confirm_reset(token, "N3wStr0ngP@ss!")


class TestPasswordResetConfig:
    async def test_no_user_model_raises(self):
        cfg = AuthConfig(signing_secret="test-secret-that-is-at-least-32-bytes!")
        svc = PasswordResetService(cfg)
        with pytest.raises(PasswordResetError, match="user_model not configured"):
            await svc.request_reset("user@example.com")

    def test_config_rejects_invalid_token_lifetime(self):
        cfg = AuthConfig(password_reset_token_lifetime=0)
        with pytest.raises(ConfigurationError, match="password_reset_token_lifetime"):
            cfg.validate()

    def test_config_rejects_invalid_rate_limit_max_attempts(self):
        cfg = AuthConfig(password_reset_rate_limit_max_attempts=0)
        with pytest.raises(ConfigurationError, match="password_reset_rate_limit_max_attempts"):
            cfg.validate()

    def test_config_rejects_invalid_rate_limit_window(self):
        cfg = AuthConfig(password_reset_rate_limit_window=-1)
        with pytest.raises(ConfigurationError, match="password_reset_rate_limit_window"):
            cfg.validate()


class TestPasswordResetEndToEnd:
    async def test_full_flow(self):
        from tortoise_auth.services.auth import AuthService

        await _create_user()
        cfg = make_config()
        svc = PasswordResetService(cfg)
        tokens: list[str] = []

        @emitter.on("password_reset_requested")
        async def handler(**kwargs: object) -> None:
            tokens.append(kwargs["token"])  # type: ignore[arg-type]

        # Step 1: Request reset
        await svc.request_reset("user@example.com")
        assert len(tokens) == 1

        # Step 2: Confirm reset with new password
        await svc.confirm_reset(tokens[0], "Brand-N3w-P@ss!")

        # Step 3: Verify login with new password
        auth_svc = AuthService(cfg)
        result = await auth_svc.login("user@example.com", "Brand-N3w-P@ss!")
        assert result.user.email == "user@example.com"
