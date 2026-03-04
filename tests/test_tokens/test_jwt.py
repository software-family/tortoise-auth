"""Tests for the JWT token backend."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import jwt
import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.models.jwt_blacklist import BlacklistedToken, OutstandingToken
from tortoise_auth.tokens import TokenPair, TokenPayload
from tortoise_auth.tokens.jwt import JWTBackend

SECRET = "test-jwt-secret-key-for-testing!"


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(jwt_secret=SECRET, **overrides)


def make_blacklist_config(**overrides: object) -> AuthConfig:
    return AuthConfig(jwt_secret=SECRET, jwt_blacklist_enabled=True, **overrides)


class TestJWTBackendCreateTokens:
    async def test_create_returns_token_pair(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        assert isinstance(pair, TokenPair)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.access_token != pair.refresh_token

    async def test_access_token_claims(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = jwt.decode(pair.access_token, SECRET, algorithms=["HS256"])
        assert payload["sub"] == "42"
        assert payload["token_type"] == "access"
        assert "jti" in payload
        assert "iat" in payload
        assert "exp" in payload

    async def test_refresh_token_claims(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = jwt.decode(pair.refresh_token, SECRET, algorithms=["HS256"])
        assert payload["sub"] == "42"
        assert payload["token_type"] == "refresh"

    async def test_extra_claims(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42", role="admin", scope="read")
        payload = jwt.decode(pair.access_token, SECRET, algorithms=["HS256"])
        assert payload["extra"] == {"role": "admin", "scope": "read"}

    async def test_unique_jtis(self):
        backend = JWTBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        p1 = jwt.decode(pair1.access_token, SECRET, algorithms=["HS256"])
        p2 = jwt.decode(pair2.access_token, SECRET, algorithms=["HS256"])
        assert p1["jti"] != p2["jti"]

    async def test_issuer_claim(self):
        backend = JWTBackend(make_config(jwt_issuer="myapp"))
        pair = await backend.create_tokens("42")
        payload = jwt.decode(
            pair.access_token,
            SECRET,
            algorithms=["HS256"],
            issuer="myapp",
            options={"verify_aud": False},
        )
        assert payload["iss"] == "myapp"

    async def test_audience_claim(self):
        backend = JWTBackend(make_config(jwt_audience="myapi"))
        pair = await backend.create_tokens("42")
        payload = jwt.decode(
            pair.access_token,
            SECRET,
            algorithms=["HS256"],
            audience="myapi",
        )
        assert payload["aud"] == "myapi"

    async def test_token_lifetimes(self):
        cfg = make_config(access_token_lifetime=300, refresh_token_lifetime=3600)
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        access = jwt.decode(pair.access_token, SECRET, algorithms=["HS256"])
        refresh = jwt.decode(pair.refresh_token, SECRET, algorithms=["HS256"])
        assert access["exp"] - access["iat"] == 300
        assert refresh["exp"] - refresh["iat"] == 3600

    async def test_no_extra_claims_when_empty(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = jwt.decode(pair.access_token, SECRET, algorithms=["HS256"])
        assert "extra" not in payload


class TestJWTBackendVerifyToken:
    async def test_verify_access_token(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.access_token, token_type="access")
        assert isinstance(payload, TokenPayload)
        assert payload.sub == "42"
        assert payload.token_type == "access"
        assert payload.jti

    async def test_verify_refresh_token(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.refresh_token, token_type="refresh")
        assert payload.sub == "42"
        assert payload.token_type == "refresh"

    async def test_verify_expired_token(self):
        cfg = make_config(access_token_lifetime=0)
        backend = JWTBackend(cfg)
        # Build a token that expires immediately
        now = int(time.time())
        token = jwt.encode(
            {"sub": "42", "token_type": "access", "jti": "abc", "iat": now, "exp": now - 1},
            SECRET,
            algorithm="HS256",
        )
        with pytest.raises(TokenExpiredError):
            await backend.verify_token(token)

    async def test_verify_invalid_token(self):
        backend = JWTBackend(make_config())
        with pytest.raises(TokenInvalidError, match="Invalid token"):
            await backend.verify_token("not-a-jwt")

    async def test_verify_wrong_type(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        with pytest.raises(TokenInvalidError, match="Expected token type"):
            await backend.verify_token(pair.access_token, token_type="refresh")

    async def test_verify_wrong_secret(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        other_backend = JWTBackend(AuthConfig(jwt_secret="wrong-secret-that-is-at-least-32-bytes!"))
        with pytest.raises(TokenInvalidError, match="Invalid token"):
            await other_backend.verify_token(pair.access_token)

    async def test_verify_issuer_mismatch(self):
        backend = JWTBackend(make_config(jwt_issuer="myapp"))
        pair = await backend.create_tokens("42")
        other_backend = JWTBackend(make_config(jwt_issuer="other"))
        with pytest.raises(TokenInvalidError, match="Invalid token"):
            await other_backend.verify_token(pair.access_token)

    async def test_verify_missing_jti(self):
        backend = JWTBackend(make_config())
        now = int(time.time())
        token = jwt.encode(
            {"sub": "42", "token_type": "access", "iat": now, "exp": now + 900},
            SECRET,
            algorithm="HS256",
        )
        with pytest.raises(TokenInvalidError, match="missing jti"):
            await backend.verify_token(token)

    async def test_verify_unknown_token_type(self):
        backend = JWTBackend(make_config())
        with pytest.raises(TokenInvalidError, match="Unknown token type"):
            await backend.verify_token("some-token", token_type="unknown")

    async def test_verify_returns_extra_claims(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42", role="admin")
        payload = await backend.verify_token(pair.access_token)
        assert payload.extra == {"role": "admin"}

    async def test_verify_returns_none_extra_when_no_extra(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.access_token)
        assert payload.extra is None


class TestJWTBackendRevocationWithoutBlacklist:
    async def test_revoke_is_noop(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        # Token still valid because blacklist is disabled
        payload = await backend.verify_token(pair.access_token)
        assert payload.sub == "42"

    async def test_revoke_all_is_noop(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_all_for_user("42")
        # Token still valid
        payload = await backend.verify_token(pair.access_token)
        assert payload.sub == "42"


class TestJWTBackendBlacklist:
    async def test_revoke_token(self):
        backend = JWTBackend(make_blacklist_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.access_token)

    async def test_revoke_refresh_token(self):
        backend = JWTBackend(make_blacklist_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.refresh_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.refresh_token, token_type="refresh")

    async def test_revoke_all_for_user(self):
        backend = JWTBackend(make_blacklist_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        pair3 = await backend.create_tokens("99")
        await backend.revoke_all_for_user("42")

        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair1.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair2.access_token)
        # User 99's token unaffected
        payload = await backend.verify_token(pair3.access_token)
        assert payload.sub == "99"

    async def test_revoke_idempotent(self):
        backend = JWTBackend(make_blacklist_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        await backend.revoke_token(pair.access_token)  # Should not raise
        assert (
            await BlacklistedToken.filter(
                jti=jwt.decode(pair.access_token, SECRET, algorithms=["HS256"])["jti"]
            ).count()
            == 1
        )

    async def test_outstanding_tokens_created(self):
        backend = JWTBackend(make_blacklist_config())
        await backend.create_tokens("42")
        assert await OutstandingToken.filter(user_id="42").count() == 2

    async def test_outstanding_token_types(self):
        backend = JWTBackend(make_blacklist_config())
        await backend.create_tokens("42")
        assert await OutstandingToken.filter(user_id="42", token_type="access").count() == 1
        assert await OutstandingToken.filter(user_id="42", token_type="refresh").count() == 1

    async def test_no_outstanding_tokens_without_blacklist(self):
        backend = JWTBackend(make_config())
        await backend.create_tokens("42")
        assert await OutstandingToken.filter(user_id="42").count() == 0

    async def test_revoke_expired_token(self):
        """Revoking an already-expired token should still blacklist it."""
        backend = JWTBackend(make_blacklist_config())
        now = int(time.time())
        token = jwt.encode(
            {"sub": "42", "token_type": "access", "jti": "expired-jti", "iat": now, "exp": now - 1},
            SECRET,
            algorithm="HS256",
        )
        await backend.revoke_token(token)
        assert await BlacklistedToken.filter(jti="expired-jti").exists()

    async def test_revoke_invalid_token_is_noop(self):
        backend = JWTBackend(make_blacklist_config())
        await backend.revoke_token("not-a-jwt")  # Should not raise

    async def test_revoke_does_not_affect_other_tokens(self):
        backend = JWTBackend(make_blacklist_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        await backend.revoke_token(pair1.access_token)
        payload = await backend.verify_token(pair2.access_token)
        assert payload.sub == "42"


class TestJWTBackendCleanup:
    async def test_cleanup_expired(self):
        backend = JWTBackend(make_blacklist_config())
        pair = await backend.create_tokens("42")
        # Force expiration on outstanding tokens
        past = datetime(2020, 1, 1, tzinfo=UTC)
        await OutstandingToken.filter(user_id="42").update(expires_at=past)
        # Blacklist one of them
        access_jti = jwt.decode(pair.access_token, SECRET, algorithms=["HS256"])["jti"]
        await BlacklistedToken.create(jti=access_jti)

        deleted = await backend.cleanup_expired()
        assert deleted >= 3  # 2 outstanding + 1 blacklisted
        assert await OutstandingToken.filter(user_id="42").count() == 0
        assert await BlacklistedToken.filter(jti=access_jti).count() == 0

    async def test_cleanup_does_not_delete_valid_tokens(self):
        backend = JWTBackend(make_blacklist_config())
        await backend.create_tokens("42")
        deleted = await backend.cleanup_expired()
        assert deleted == 0
        assert await OutstandingToken.filter(user_id="42").count() == 2

    async def test_cleanup_returns_zero_when_empty(self):
        backend = JWTBackend(make_blacklist_config())
        deleted = await backend.cleanup_expired()
        assert deleted == 0


class TestJWTBackendSecretFallback:
    async def test_falls_back_to_signing_secret(self):
        cfg = AuthConfig(signing_secret="fallback-secret-that-is-at-least-32b")
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        # Verify the token was signed with the signing_secret
        secret = "fallback-secret-that-is-at-least-32b"
        payload = jwt.decode(pair.access_token, secret, algorithms=["HS256"])
        assert payload["sub"] == "42"

    async def test_jwt_secret_takes_precedence(self):
        jwt_secret = "jwt-secret-that-is-at-least-32-bytes!"
        signing_secret = "signing-secret-at-least-32-bytes!!"
        cfg = AuthConfig(jwt_secret=jwt_secret, signing_secret=signing_secret)
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        payload = jwt.decode(pair.access_token, jwt_secret, algorithms=["HS256"])
        assert payload["sub"] == "42"
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(pair.access_token, signing_secret, algorithms=["HS256"])


class TestJWTBackendWithAuthService:
    async def test_login_with_jwt_backend(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="jwt@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(
            user_model="models.MinimalUser",
            jwt_secret=SECRET,
        )
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("jwt@example.com", "Str0ngP@ss!")
        assert result.access_token
        assert result.refresh_token

    async def test_authenticate_with_jwt_backend(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="jwt2@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(
            user_model="models.MinimalUser",
            jwt_secret=SECRET,
        )
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("jwt2@example.com", "Str0ngP@ss!")
        authenticated_user = await svc.authenticate(result.access_token)
        assert authenticated_user.pk == user.pk

    async def test_refresh_with_jwt_backend(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        await MinimalUser.create(email="jwt3@example.com")
        user = await MinimalUser.first()
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(
            user_model="models.MinimalUser",
            jwt_secret=SECRET,
            jwt_blacklist_enabled=True,
        )
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("jwt3@example.com", "Str0ngP@ss!")
        new_tokens = await svc.refresh(result.refresh_token)
        assert isinstance(new_tokens, TokenPair)
        assert new_tokens.access_token != result.access_token

    async def test_logout_with_jwt_blacklist(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        await MinimalUser.create(email="jwt4@example.com")
        user = await MinimalUser.filter(email="jwt4@example.com").first()
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(
            user_model="models.MinimalUser",
            jwt_secret=SECRET,
            jwt_blacklist_enabled=True,
        )
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("jwt4@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result.access_token)

    async def test_logout_all_with_jwt_blacklist(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        await MinimalUser.create(email="jwt5@example.com")
        user = await MinimalUser.filter(email="jwt5@example.com").first()
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(
            user_model="models.MinimalUser",
            jwt_secret=SECRET,
            jwt_blacklist_enabled=True,
        )
        backend = JWTBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result1 = await svc.login("jwt5@example.com", "Str0ngP@ss!")
        result2 = await svc.login("jwt5@example.com", "Str0ngP@ss!")
        await svc.logout_all(str(user.pk))

        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result1.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result2.access_token)
