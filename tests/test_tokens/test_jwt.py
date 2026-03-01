"""Tests for the JWT token backend."""


import jwt
import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.tokens import TokenPair, TokenPayload
from tortoise_auth.tokens.jwt import JWTBackend


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(jwt_secret="test-jwt-secret-key-at-least-32-bytes!!", **overrides)


class TestJWTBackendCreateTokens:
    async def test_create_returns_token_pair(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        assert isinstance(pair, TokenPair)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.access_token != pair.refresh_token

    async def test_tokens_are_decodable(self):
        cfg = make_config()
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        access_payload = jwt.decode(
            pair.access_token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm]
        )
        assert access_payload["sub"] == "42"
        assert access_payload["type"] == "access"
        assert "jti" in access_payload
        assert "iat" in access_payload
        assert "exp" in access_payload

    async def test_refresh_token_type(self):
        cfg = make_config()
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        refresh_payload = jwt.decode(
            pair.refresh_token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm]
        )
        assert refresh_payload["type"] == "refresh"

    async def test_extra_claims(self):
        cfg = make_config()
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42", role="admin")
        payload = jwt.decode(
            pair.access_token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm]
        )
        assert payload["extra"] == {"role": "admin"}

    async def test_no_extra_in_refresh(self):
        cfg = make_config()
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42", role="admin")
        payload = jwt.decode(
            pair.refresh_token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm]
        )
        assert "extra" not in payload

    async def test_issuer_and_audience(self):
        cfg = make_config(jwt_issuer="myapp", jwt_audience="myapi")
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        payload = jwt.decode(
            pair.access_token,
            cfg.jwt_secret,
            algorithms=[cfg.jwt_algorithm],
            audience="myapi",
        )
        assert payload["iss"] == "myapp"
        assert payload["aud"] == "myapi"

    async def test_unique_jtis(self):
        backend = JWTBackend(make_config())
        cfg = make_config()
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        p1 = jwt.decode(pair1.access_token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm])
        p2 = jwt.decode(pair2.access_token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm])
        assert p1["jti"] != p2["jti"]


class TestJWTBackendVerifyToken:
    async def test_verify_access_token(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.access_token, token_type="access")
        assert isinstance(payload, TokenPayload)
        assert payload.sub == "42"
        assert payload.token_type == "access"
        assert payload.jti
        assert payload.iat > 0
        assert payload.exp > payload.iat

    async def test_verify_refresh_token(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.refresh_token, token_type="refresh")
        assert payload.sub == "42"
        assert payload.token_type == "refresh"

    async def test_wrong_token_type(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        with pytest.raises(TokenInvalidError, match="Expected token type"):
            await backend.verify_token(pair.access_token, token_type="refresh")

    async def test_expired_token(self):
        cfg = make_config(jwt_access_token_lifetime=0)
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        # Token expires immediately (lifetime=0)
        import time as _time

        _time.sleep(1)
        with pytest.raises(TokenExpiredError):
            await backend.verify_token(pair.access_token)

    async def test_invalid_token(self):
        backend = JWTBackend(make_config())
        with pytest.raises(TokenInvalidError):
            await backend.verify_token("not-a-valid-jwt")

    async def test_wrong_secret(self):
        backend1 = JWTBackend(AuthConfig(jwt_secret="secret-key-1-at-least-32-bytes!!"))
        backend2 = JWTBackend(AuthConfig(jwt_secret="secret-key-2-at-least-32-bytes!!"))
        pair = await backend1.create_tokens("42")
        with pytest.raises(TokenInvalidError):
            await backend2.verify_token(pair.access_token)

    async def test_verify_with_issuer(self):
        cfg = make_config(jwt_issuer="myapp")
        backend = JWTBackend(cfg)
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.access_token)
        assert payload.sub == "42"

    async def test_verify_with_extra(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42", role="admin")
        payload = await backend.verify_token(pair.access_token)
        assert payload.extra == {"role": "admin"}


class TestJWTBackendRevocation:
    async def test_revoke_token(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.access_token)

    async def test_revoke_does_not_affect_other_tokens(self):
        backend = JWTBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        await backend.revoke_token(pair1.access_token)
        # pair2 should still work
        payload = await backend.verify_token(pair2.access_token)
        assert payload.sub == "42"

    async def test_revoke_invalid_token_no_error(self):
        backend = JWTBackend(make_config())
        await backend.revoke_token("invalid-token")  # Should not raise

    async def test_revoke_all_for_user_is_noop(self):
        backend = JWTBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_all_for_user("42")
        # JWT backend can't revoke all, so token still works
        payload = await backend.verify_token(pair.access_token)
        assert payload.sub == "42"
