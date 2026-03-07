"""Tests for the database token backend."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.models.tokens import AccessToken, RefreshToken, hash_token
from tortoise_auth.tokens import TokenBackend, TokenPair, TokenPayload
from tortoise_auth.tokens.database import DatabaseTokenBackend


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(**overrides)


class TestDatabaseBackendCreateTokens:
    async def test_create_returns_token_pair(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        assert isinstance(pair, TokenPair)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.access_token != pair.refresh_token

    async def test_tokens_are_raw_strings_not_hashes(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        # Raw tokens should be the configured length, not 64-char hex hashes
        assert len(pair.access_token) == 64
        assert len(pair.refresh_token) == 64
        # They should not look like SHA-256 hashes (contain letters outside hex)
        # Actually they're alphanumeric, so just check they differ from stored hashes
        access_record = await AccessToken.first()
        assert access_record.token_hash != pair.access_token
        assert access_record.token_hash == hash_token(pair.access_token)

    async def test_custom_token_length(self):
        backend = DatabaseTokenBackend(make_config(token_length=32))
        pair = await backend.create_tokens("42")
        assert len(pair.access_token) == 32
        assert len(pair.refresh_token) == 32

    async def test_hashes_stored_in_db(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        access_record = await AccessToken.filter(token_hash=hash_token(pair.access_token)).first()
        refresh_record = await RefreshToken.filter(
            token_hash=hash_token(pair.refresh_token)
        ).first()
        assert access_record is not None
        assert refresh_record is not None

    async def test_unique_jtis(self):
        backend = DatabaseTokenBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        r1 = await AccessToken.filter(token_hash=hash_token(pair1.access_token)).first()
        r2 = await AccessToken.filter(token_hash=hash_token(pair2.access_token)).first()
        assert r1.jti != r2.jti

    async def test_lifetime_correctness(self):
        cfg = make_config(access_token_lifetime=300, refresh_token_lifetime=3600)
        backend = DatabaseTokenBackend(cfg)
        pair = await backend.create_tokens("42")
        access_record = await AccessToken.filter(token_hash=hash_token(pair.access_token)).first()
        refresh_record = await RefreshToken.filter(
            token_hash=hash_token(pair.refresh_token)
        ).first()
        access_delta = (access_record.expires_at - access_record.created_at).total_seconds()
        refresh_delta = (refresh_record.expires_at - refresh_record.created_at).total_seconds()
        assert access_delta == 300
        assert refresh_delta == 3600

    async def test_refresh_links_to_access_via_access_jti(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        access_record = await AccessToken.filter(token_hash=hash_token(pair.access_token)).first()
        refresh_record = await RefreshToken.filter(
            token_hash=hash_token(pair.refresh_token)
        ).first()
        assert refresh_record.access_jti == access_record.jti


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

    async def test_verify_correct_payload_fields(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        payload = await backend.verify_token(pair.access_token)
        assert payload.sub == "42"
        assert payload.token_type == "access"
        assert payload.jti
        assert payload.iat > 0
        assert payload.exp > payload.iat

    async def test_expired_raises_token_expired_error(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        # Force expiration
        past = datetime(2020, 1, 1, tzinfo=UTC)
        await AccessToken.filter(token_hash=hash_token(pair.access_token)).update(expires_at=past)
        with pytest.raises(TokenExpiredError):
            await backend.verify_token(pair.access_token)

    async def test_not_found_raises_token_invalid_error(self):
        backend = DatabaseTokenBackend(make_config())
        with pytest.raises(TokenInvalidError, match="Token not found"):
            await backend.verify_token("nonexistent-token")

    async def test_wrong_type_raises_token_invalid_error(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        # Access token verified as refresh should fail (not found in refresh table)
        with pytest.raises(TokenInvalidError, match="Token not found"):
            await backend.verify_token(pair.access_token, token_type="refresh")

    async def test_unknown_type_raises_token_invalid_error(self):
        backend = DatabaseTokenBackend(make_config())
        with pytest.raises(TokenInvalidError, match="Unknown token type"):
            await backend.verify_token("some-token", token_type="unknown")

    async def test_extra_is_always_none(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42", role="admin")
        payload = await backend.verify_token(pair.access_token)
        assert payload.extra is None


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

    async def test_revoke_not_found_is_noop(self):
        backend = DatabaseTokenBackend(make_config())
        await backend.revoke_token("nonexistent-token")  # Should not raise

    async def test_revoke_all_for_user(self):
        backend = DatabaseTokenBackend(make_config())
        pair1 = await backend.create_tokens("42")
        pair2 = await backend.create_tokens("42")
        await backend.revoke_all_for_user("42")
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair1.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair2.access_token)

    async def test_revoke_all_does_not_affect_other_users(self):
        backend = DatabaseTokenBackend(make_config())
        await backend.create_tokens("42")
        pair_other = await backend.create_tokens("99")
        await backend.revoke_all_for_user("42")
        # User 99's tokens unaffected
        payload = await backend.verify_token(pair_other.access_token)
        assert payload.sub == "99"

    async def test_revoke_is_idempotent(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        await backend.revoke_token(pair.access_token)  # Should not raise
        record = await AccessToken.filter(token_hash=hash_token(pair.access_token)).first()
        assert record.is_revoked is True

    async def test_revoked_raises_token_revoked_error(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        await backend.revoke_token(pair.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(pair.access_token)


class TestDatabaseBackendCleanup:
    async def test_deletes_expired(self):
        backend = DatabaseTokenBackend(make_config())
        pair = await backend.create_tokens("42")
        past = datetime(2020, 1, 1, tzinfo=UTC)
        await AccessToken.filter(token_hash=hash_token(pair.access_token)).update(expires_at=past)
        await RefreshToken.filter(token_hash=hash_token(pair.refresh_token)).update(expires_at=past)
        deleted = await backend.cleanup_expired()
        assert deleted == 2
        assert await AccessToken.all().count() == 0
        assert await RefreshToken.all().count() == 0

    async def test_preserves_valid(self):
        backend = DatabaseTokenBackend(make_config())
        await backend.create_tokens("42")
        deleted = await backend.cleanup_expired()
        assert deleted == 0
        assert await AccessToken.all().count() == 1
        assert await RefreshToken.all().count() == 1

    async def test_returns_zero_when_empty(self):
        backend = DatabaseTokenBackend(make_config())
        deleted = await backend.cleanup_expired()
        assert deleted == 0


class TestDatabaseBackendProtocol:
    def test_implements_token_backend(self):
        assert isinstance(DatabaseTokenBackend(), TokenBackend)


class TestDatabaseBackendWithAuthService:
    async def test_login(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="db@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(user_model="models.MinimalUser")
        backend = DatabaseTokenBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("db@example.com", "Str0ngP@ss!")
        assert result.access_token
        assert result.refresh_token

    async def test_authenticate(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="db2@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(user_model="models.MinimalUser")
        backend = DatabaseTokenBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("db2@example.com", "Str0ngP@ss!")
        authenticated_user = await svc.authenticate(result.access_token)
        assert authenticated_user.pk == user.pk

    async def test_refresh(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="db3@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(user_model="models.MinimalUser")
        backend = DatabaseTokenBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("db3@example.com", "Str0ngP@ss!")
        new_tokens = await svc.refresh(result.refresh_token)
        assert isinstance(new_tokens, TokenPair)
        assert new_tokens.access_token != result.access_token

    async def test_logout(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="db4@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(user_model="models.MinimalUser")
        backend = DatabaseTokenBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result = await svc.login("db4@example.com", "Str0ngP@ss!")
        await svc.logout(result.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result.access_token)

    async def test_logout_all(self):
        from tests.models import MinimalUser
        from tortoise_auth.services.auth import AuthService

        user = await MinimalUser.create(email="db5@example.com")
        await user.set_password("Str0ngP@ss!")

        cfg = AuthConfig(user_model="models.MinimalUser")
        backend = DatabaseTokenBackend(cfg)
        svc = AuthService(cfg, backend=backend)

        result1 = await svc.login("db5@example.com", "Str0ngP@ss!")
        result2 = await svc.login("db5@example.com", "Str0ngP@ss!")
        await svc.logout_all(str(user.pk))

        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result1.access_token)
        with pytest.raises(TokenRevokedError):
            await backend.verify_token(result2.access_token)
