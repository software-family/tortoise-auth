"""Tests for the database token backend."""

from datetime import UTC, datetime

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.models.tokens import AccessToken, RefreshToken
from tortoise_auth.tokens import TokenPair, TokenPayload
from tortoise_auth.tokens.database import DatabaseTokenBackend


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(token_backend="database", **overrides)


class TestDatabaseBackendCreateTokens:
    async def test_create_returns_token_pair(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        assert isinstance(pair, TokenPair)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.access_token != pair.refresh_token

    async def test_tokens_persisted_in_database(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        access_hash = AccessToken.hash_token(pair.access_token)
        refresh_hash = RefreshToken.hash_token(pair.refresh_token)
        assert await AccessToken.filter(token_hash=access_hash).exists()
        assert await RefreshToken.filter(token_hash=refresh_hash).exists()

    async def test_token_length(self):
        backend = DatabaseTokenBackend(make_config(db_token_length=32))
        pair = await backend.create_tokens("42")
        assert len(pair.access_token) == 32
        assert len(pair.refresh_token) == 32

    async def test_user_id_stored(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("99")
        access_hash = AccessToken.hash_token(pair.access_token)
        record = await AccessToken.filter(token_hash=access_hash).first()
        assert record is not None
        assert record.user_id == "99"

    async def test_refresh_links_to_access(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        access_hash = AccessToken.hash_token(pair.access_token)
        refresh_hash = RefreshToken.hash_token(pair.refresh_token)
        access = await AccessToken.filter(token_hash=access_hash).first()
        refresh = await RefreshToken.filter(token_hash=refresh_hash).first()
        assert access is not None
        assert refresh is not None
        assert refresh.access_jti == access.jti

    async def test_unique_jtis(self):
        backend = DatabaseTokenBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        h1 = AccessToken.hash_token(pair1.access_token)
        h2 = AccessToken.hash_token(pair2.access_token)
        a1 = await AccessToken.filter(token_hash=h1).first()
        a2 = await AccessToken.filter(token_hash=h2).first()
        assert a1 is not None and a2 is not None
        assert a1.jti != a2.jti


class TestDatabaseBackendVerifyToken:
    async def test_verify_access_token(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.access_token, token_type="access")
        assert isinstance(payload, TokenPayload)
        assert payload.sub == "42"
        assert payload.token_type == "access"
        assert payload.jti

    async def test_verify_refresh_token(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.refresh_token, token_type="refresh")
        assert payload.sub == "42"
        assert payload.token_type == "refresh"

    async def test_verify_nonexistent_token(self):
        backend = DatabaseTokenBackend(make_config())
        with pytest.raises(TokenInvalidError, match="not found"):
            await backend.verify_token("nonexistent-token")

    async def test_verify_unknown_type(self):
        backend = DatabaseTokenBackend(make_config())
        with pytest.raises(TokenInvalidError, match="Unknown token type"):
            await backend.verify_token("some-token", token_type="unknown")

    async def test_verify_expired_token(self):
        backend = DatabaseTokenBackend(make_config(jwt_access_token_lifetime=0))
        pair = await backend.create_tokens("42")
        # Force the expiration in the DB
        access_hash = AccessToken.hash_token(pair.access_token)
        await AccessToken.filter(token_hash=access_hash).update(
            expires_at=datetime(2020, 1, 1, tzinfo=UTC)
        )
        with pytest.raises(TokenExpiredError):
            await backend.verify_token(pair.access_token)

    async def test_verify_revoked_token(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        access_hash = AccessToken.hash_token(pair.access_token)
        await AccessToken.filter(token_hash=access_hash).update(is_revoked=True)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.access_token)


class TestDatabaseBackendRevocation:
    async def test_revoke_access_token(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.access_token)

    async def test_revoke_refresh_token(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.refresh_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.refresh_token, token_type="refresh")

    async def test_revoke_nonexistent_token(self):
        backend = DatabaseTokenBackend(make_config())
        # Should not raise
        await backend.revoke_token("nonexistent-token")

    async def test_revoke_all_for_user(self):
        backend = DatabaseTokenBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        pair3 = await backend.create_tokens("99")
        await backend.revoke_all_for_user("42")

        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair1.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair2.access_token)
        # User 99's token should be unaffected
        payload = await backend.verify_token(pair3.access_token)
        assert payload.sub == "99"

    async def test_revoke_does_not_affect_other_tokens(self):
        backend = DatabaseTokenBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        await backend.revoke_token(pair1.access_token)
        payload = await backend.verify_token(pair2.access_token)
        assert payload.sub == "42"


class TestDatabaseBackendCleanup:
    async def test_cleanup_expired(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        # Force expiration
        access_hash = AccessToken.hash_token(pair.access_token)
        refresh_hash = RefreshToken.hash_token(pair.refresh_token)
        past = datetime(2020, 1, 1, tzinfo=UTC)
        await AccessToken.filter(token_hash=access_hash).update(expires_at=past)
        await RefreshToken.filter(token_hash=refresh_hash).update(expires_at=past)

        deleted = await backend.cleanup_expired()
        assert deleted == 2
        assert not await AccessToken.filter(token_hash=access_hash).exists()
        assert not await RefreshToken.filter(token_hash=refresh_hash).exists()

    async def test_cleanup_does_not_delete_valid_tokens(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        deleted = await backend.cleanup_expired()
        assert deleted == 0
        # Token still exists
        payload = await backend.verify_token(pair.access_token)
        assert payload.sub == "42"
