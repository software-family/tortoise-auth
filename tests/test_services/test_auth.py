"""Tests for the AuthService."""

import pytest

from tests.models import MinimalUser
from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    AuthenticationError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.services.auth import AuthService
from tortoise_auth.tokens import AuthResult, TokenPair
from tortoise_auth.tokens.database import DatabaseTokenBackend
from tortoise_auth.tokens.jwt import JWTBackend

JWT_SECRET = "test-jwt-secret-key-for-auth-service-32b!"


def make_jwt_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        jwt_secret=JWT_SECRET,
        token_backend="jwt",
        **overrides,
    )


def make_db_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        token_backend="database",
        jwt_access_token_lifetime=900,
        jwt_refresh_token_lifetime=604_800,
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


class TestAuthServiceLoginJWT:
    async def test_login_success(self):
        user = await _create_user()
        svc = AuthService(make_jwt_config())
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        assert isinstance(result, AuthResult)
        assert result.user.pk == user.pk
        assert result.access_token
        assert result.refresh_token

    async def test_login_returns_valid_tokens(self):
        await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        # Tokens should be verifiable
        backend = JWTBackend(cfg)
        payload = await backend.verify_token(result.access_token)
        assert payload.sub == str((await MinimalUser.first()).pk)

    async def test_login_updates_last_login(self):
        user = await _create_user()
        assert user.last_login is None
        svc = AuthService(make_jwt_config())
        await svc.login("user@example.com", "Str0ngP@ss!")
        await user.refresh_from_db()
        assert user.last_login is not None

    async def test_login_wrong_password(self):
        await _create_user()
        svc = AuthService(make_jwt_config())
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("user@example.com", "wrong-password")

    async def test_login_unknown_user(self):
        svc = AuthService(make_jwt_config())
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("nobody@example.com", "password")

    async def test_login_inactive_user(self):
        user = await _create_user()
        user.is_active = False
        await user.save(update_fields=["is_active"])
        svc = AuthService(make_jwt_config())
        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await svc.login("user@example.com", "Str0ngP@ss!")

    async def test_login_emits_user_login_event(self):
        await _create_user()
        svc = AuthService(make_jwt_config())
        events: list[object] = []

        @emitter.on("user_login")
        async def handler(user: object) -> None:
            events.append(user)

        await svc.login("user@example.com", "Str0ngP@ss!")
        assert len(events) == 1

    async def test_login_failed_emits_event(self):
        await _create_user()
        svc = AuthService(make_jwt_config())
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
        svc = AuthService(make_jwt_config())
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        tokens = result.tokens
        assert isinstance(tokens, TokenPair)
        assert tokens.access_token == result.access_token
        assert tokens.refresh_token == result.refresh_token

    async def test_login_with_extra_claims(self):
        await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!", role="admin")
        backend = JWTBackend(cfg)
        payload = await backend.verify_token(result.access_token)
        assert payload.extra == {"role": "admin"}


class TestAuthServiceAuthenticateJWT:
    async def test_authenticate_success(self):
        user = await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        authenticated_user = await svc.authenticate(result.access_token)
        assert authenticated_user.pk == user.pk

    async def test_authenticate_invalid_token(self):
        svc = AuthService(make_jwt_config())
        with pytest.raises(TokenInvalidError):
            await svc.authenticate("invalid-token")

    async def test_authenticate_inactive_user(self):
        user = await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        user.is_active = False
        await user.save(update_fields=["is_active"])
        with pytest.raises(AuthenticationError, match="inactive"):
            await svc.authenticate(result.access_token)


class TestAuthServiceRefreshJWT:
    async def test_refresh_success(self):
        await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        new_tokens = await svc.refresh(result.refresh_token)
        assert isinstance(new_tokens, TokenPair)
        assert new_tokens.access_token
        assert new_tokens.refresh_token
        assert new_tokens.access_token != result.access_token

    async def test_refresh_revokes_old_token(self):
        await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg, backend=JWTBackend(cfg))
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.refresh(result.refresh_token)
        with pytest.raises(TokenRevokedError):
            await svc.backend.verify_token(result.refresh_token, token_type="refresh")


class TestAuthServiceLogoutJWT:
    async def test_logout(self):
        await _create_user()
        cfg = make_jwt_config()
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result.access_token)

    async def test_logout_emits_event(self):
        await _create_user()
        cfg = make_jwt_config()
        svc = AuthService(cfg, backend=JWTBackend(cfg))
        events: list[object] = []

        @emitter.on("user_logout")
        async def handler(user: object) -> None:
            events.append(user)

        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        assert len(events) == 1


class TestAuthServiceLoginDB:
    async def test_login_success_database(self):
        user = await _create_user()
        cfg = make_db_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        assert result.user.pk == user.pk
        assert result.access_token
        assert result.refresh_token

    async def test_authenticate_database(self):
        user = await _create_user()
        cfg = make_db_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        authenticated_user = await svc.authenticate(result.access_token)
        assert authenticated_user.pk == user.pk

    async def test_refresh_database(self):
        await _create_user()
        cfg = make_db_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        new_tokens = await svc.refresh(result.refresh_token)
        assert isinstance(new_tokens, TokenPair)
        assert new_tokens.access_token != result.access_token

    async def test_logout_database(self):
        await _create_user()
        cfg = make_db_config()
        backend = DatabaseTokenBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        result = await svc.login("user@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result.access_token)

    async def test_logout_all_database(self):
        user = await _create_user()
        cfg = make_db_config()
        backend = DatabaseTokenBackend(cfg)
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
        cfg = AuthConfig(jwt_secret=JWT_SECRET)
        svc = AuthService(cfg)
        with pytest.raises(AuthenticationError, match="user_model not configured"):
            await svc.login("user@example.com", "password")

    async def test_invalid_user_model_format(self):
        cfg = AuthConfig(jwt_secret=JWT_SECRET, user_model="NoDotsHere")
        svc = AuthService(cfg)
        with pytest.raises(AuthenticationError, match="Invalid user_model format"):
            await svc.login("user@example.com", "password")

    async def test_user_model_not_in_registry(self):
        cfg = AuthConfig(jwt_secret=JWT_SECRET, user_model="nonexistent.Model")
        svc = AuthService(cfg)
        with pytest.raises(AuthenticationError, match="not found"):
            await svc.login("user@example.com", "password")

    def test_default_backend_is_jwt(self):
        cfg = make_jwt_config()
        svc = AuthService(cfg)
        assert isinstance(svc.backend, JWTBackend)

    def test_database_backend_from_config(self):
        cfg = make_db_config()
        svc = AuthService(cfg)
        assert isinstance(svc.backend, DatabaseTokenBackend)

    def test_explicit_backend(self):
        cfg = make_jwt_config()
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)
        assert svc.backend is backend
