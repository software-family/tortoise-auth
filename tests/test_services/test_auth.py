"""Tests for the AuthService."""

from unittest.mock import patch

import pytest

from tests.models import MinimalUser
from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    AuthenticationError,
    InvalidPasswordError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.services.auth import AuthService
from tortoise_auth.tokens import AuthResult, TokenPair
from tortoise_auth.tokens.jwt import JWTBackend


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        access_token_lifetime=900,
        refresh_token_lifetime=604_800,
        jwt_secret="test-secret-key",
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


class TestAuthServiceLogin:
    async def test_login_success(self):
        user = await _create_user()
        svc = AuthService(make_config())
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        assert isinstance(result, AuthResult)
        assert result.user.pk == user.pk
        assert result.access_token
        assert result.refresh_token

    async def test_login_returns_valid_tokens(self):
        await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        backend = JWTBackend(cfg)
        payload = await backend.verify_token(result.access_token)
        assert payload.sub == str((await MinimalUser.first()).pk)

    async def test_login_updates_last_login(self):
        user = await _create_user()
        assert user.last_login is None
        svc = AuthService(make_config())
        await svc.login("user@example.com", "Str0ngP@ss!")
        await user.refresh_from_db()
        assert user.last_login is not None

    async def test_login_wrong_password(self):
        await _create_user()
        svc = AuthService(make_config())
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("user@example.com", "wrong-password")

    async def test_login_unknown_user(self):
        svc = AuthService(make_config())
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("nobody@example.com", "password")

    async def test_login_inactive_user(self):
        user = await _create_user()
        user.is_active = False
        await user.save(update_fields=["is_active"])
        svc = AuthService(make_config())
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("user@example.com", "Str0ngP@ss!")

    async def test_login_emits_user_login_event(self):
        await _create_user()
        svc = AuthService(make_config())
        events: list[object] = []

        @emitter.on("user_login")
        async def handler(user: object) -> None:
            events.append(user)

        await svc.login("user@example.com", "Str0ngP@ss!")
        assert len(events) == 1

    async def test_login_failed_emits_event(self):
        await _create_user()
        svc = AuthService(make_config())
        events: list[dict[str, str]] = []

        @emitter.on("user_login_failed")
        async def handler(**kwargs: str) -> None:
            events.append(kwargs)

        with pytest.raises(AuthenticationError):
            await svc.login("user@example.com", "wrong")
        assert len(events) == 1
        assert events[0]["reason"] == "bad_password"

    async def test_auth_result_tokens_property(self):
        await _create_user()
        svc = AuthService(make_config())
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        tokens = result.tokens
        assert isinstance(tokens, TokenPair)
        assert tokens.access_token == result.access_token
        assert tokens.refresh_token == result.refresh_token


class TestAuthServiceAuthenticate:
    async def test_authenticate_success(self):
        user = await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        authenticated_user = await svc.authenticate(result.access_token)
        assert authenticated_user.pk == user.pk

    async def test_authenticate_invalid_token(self):
        svc = AuthService(make_config())
        with pytest.raises(TokenInvalidError):
            await svc.authenticate("invalid-token")

    async def test_authenticate_inactive_user(self):
        user = await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        user.is_active = False
        await user.save(update_fields=["is_active"])
        with pytest.raises(AuthenticationError, match="inactive"):
            await svc.authenticate(result.access_token)


class TestAuthServiceRefresh:
    async def test_refresh_success(self):
        await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        new_tokens = await svc.refresh(result.refresh_token)
        assert isinstance(new_tokens, TokenPair)
        assert new_tokens.access_token
        assert new_tokens.refresh_token
        assert new_tokens.access_token != result.access_token

    async def test_refresh_revokes_old_token(self):
        await _create_user()
        cfg = make_config()
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.refresh(result.refresh_token)
        with pytest.raises(TokenRevokedError):
            await svc.backend.verify_token(result.refresh_token, token_type="refresh")


class TestAuthServiceLogout:
    async def test_logout(self):
        await _create_user()
        cfg = make_config()
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result.access_token)

    async def test_logout_emits_event(self):
        await _create_user()
        cfg = make_config()
        svc = AuthService(cfg, backend=JWTBackend(cfg))
        events: list[object] = []

        @emitter.on("user_logout")
        async def handler(user: object) -> None:
            events.append(user)

        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        assert len(events) == 1

    async def test_logout_all(self):
        user = await _create_user()
        cfg = make_config()
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        result1 = await svc.login("user@example.com", "Str0ngP@ss!")
        result2 = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.logout_all(str(user.pk))
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result1.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result2.access_token)


class TestAuthServiceConfig:
    async def test_no_user_model_configured(self):
        cfg = AuthConfig()
        svc = AuthService(cfg)
        with pytest.raises(AuthenticationError, match="user_model not configured"):
            await svc.login("user@example.com", "password")

    async def test_invalid_user_model_format(self):
        cfg = AuthConfig(user_model="NoDotsHere")
        svc = AuthService(cfg)
        with pytest.raises(AuthenticationError, match="Invalid user_model format"):
            await svc.login("user@example.com", "password")

    async def test_user_model_not_in_registry(self):
        cfg = AuthConfig(user_model="nonexistent.Model")
        svc = AuthService(cfg)
        with pytest.raises(AuthenticationError, match="not found"):
            await svc.login("user@example.com", "password")

    def test_default_backend_is_jwt(self):
        cfg = make_config()
        svc = AuthService(cfg)
        assert isinstance(svc.backend, JWTBackend)

    def test_explicit_backend(self):
        cfg = make_config()
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        assert svc.backend is backend


class TestAuthServiceTimingAttack:
    async def test_dummy_verify_called_for_unknown_user(self):
        svc = AuthService(make_config())
        with patch.object(svc, "_dummy_verify") as mock_dummy:
            with pytest.raises(AuthenticationError):
                await svc.login("nobody@example.com", "password")
            mock_dummy.assert_called_once_with("password")

    async def test_dummy_verify_called_for_inactive_user(self):
        user = await _create_user()
        user.is_active = False
        await user.save(update_fields=["is_active"])
        svc = AuthService(make_config())
        with patch.object(svc, "_dummy_verify") as mock_dummy:
            with pytest.raises(AuthenticationError):
                await svc.login("user@example.com", "Str0ngP@ss!")
            mock_dummy.assert_called_once_with("Str0ngP@ss!")

    async def test_dummy_verify_not_called_for_valid_user(self):
        await _create_user()
        svc = AuthService(make_config())
        with patch.object(svc, "_dummy_verify") as mock_dummy:
            await svc.login("user@example.com", "Str0ngP@ss!")
            mock_dummy.assert_not_called()


class TestAuthServicePasswordLengthCap:
    async def test_set_password_rejects_too_long(self):
        user = await _create_user()
        long_password = "A" * 4097
        with pytest.raises(InvalidPasswordError, match="maximum length"):
            await user.set_password(long_password)

    async def test_check_password_rejects_too_long(self):
        user = await _create_user()
        long_password = "A" * 4097
        result = await user.check_password(long_password)
        assert result is False

    async def test_login_with_too_long_password(self):
        await _create_user()
        svc = AuthService(make_config())
        long_password = "A" * 4097
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("user@example.com", long_password)
