"""Tests for token database models."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from tortoise.exceptions import IntegrityError

from tortoise_auth.models.tokens import AccessToken, RefreshToken


class TestTokenMixin:
    def test_hash_token(self):
        raw = "my-secret-token"
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert AccessToken.hash_token(raw) == expected

    def test_hash_token_deterministic(self):
        assert AccessToken.hash_token("abc") == AccessToken.hash_token("abc")

    def test_hash_token_different_inputs(self):
        assert AccessToken.hash_token("a") != AccessToken.hash_token("b")

    def test_generate_token_length(self):
        token = AccessToken.generate_token(32)
        assert len(token) == 32

    def test_generate_token_unique(self):
        t1 = AccessToken.generate_token(64)
        t2 = AccessToken.generate_token(64)
        assert t1 != t2


class TestAccessToken:
    async def test_create_access_token(self):
        now = datetime.now(tz=UTC)
        token = await AccessToken.create(
            token_hash="a" * 64,
            jti="jti-access-1",
            user_id="42",
            expires_at=now + timedelta(hours=1),
        )
        assert token.id is not None
        assert token.user_id == "42"
        assert token.is_revoked is False

    async def test_is_valid(self):
        now = datetime.now(tz=UTC)
        token = await AccessToken.create(
            token_hash="b" * 64,
            jti="jti-access-2",
            user_id="42",
            expires_at=now + timedelta(hours=1),
        )
        assert token.is_valid is True
        assert token.is_expired is False

    async def test_is_expired(self):
        past = datetime(2020, 1, 1, tzinfo=UTC)
        token = await AccessToken.create(
            token_hash="c" * 64,
            jti="jti-access-3",
            user_id="42",
            expires_at=past,
        )
        assert token.is_expired is True
        assert token.is_valid is False

    async def test_is_revoked(self):
        now = datetime.now(tz=UTC)
        token = await AccessToken.create(
            token_hash="d" * 64,
            jti="jti-access-4",
            user_id="42",
            expires_at=now + timedelta(hours=1),
            is_revoked=True,
        )
        assert token.is_revoked is True
        assert token.is_valid is False

    async def test_repr(self):
        now = datetime.now(tz=UTC)
        token = await AccessToken.create(
            token_hash="e" * 64,
            jti="jti-access-5",
            user_id="42",
            expires_at=now + timedelta(hours=1),
        )
        assert "jti-access-5" in repr(token)
        assert "42" in repr(token)

    async def test_unique_token_hash(self):
        now = datetime.now(tz=UTC)
        await AccessToken.create(
            token_hash="f" * 64,
            jti="jti-access-6a",
            user_id="42",
            expires_at=now + timedelta(hours=1),
        )
        with pytest.raises(IntegrityError):
            await AccessToken.create(
                token_hash="f" * 64,
                jti="jti-access-6b",
                user_id="42",
                expires_at=now + timedelta(hours=1),
            )

    async def test_unique_jti(self):
        now = datetime.now(tz=UTC)
        await AccessToken.create(
            token_hash="g" * 64,
            jti="same-jti",
            user_id="42",
            expires_at=now + timedelta(hours=1),
        )
        with pytest.raises(IntegrityError):
            await AccessToken.create(
                token_hash="h" * 64,
                jti="same-jti",
                user_id="42",
                expires_at=now + timedelta(hours=1),
            )


class TestRefreshToken:
    async def test_create_refresh_token(self):
        now = datetime.now(tz=UTC)
        token = await RefreshToken.create(
            token_hash="r" * 64,
            jti="jti-refresh-1",
            user_id="42",
            access_jti="access-jti-1",
            expires_at=now + timedelta(days=7),
        )
        assert token.id is not None
        assert token.user_id == "42"
        assert token.access_jti == "access-jti-1"

    async def test_is_valid(self):
        now = datetime.now(tz=UTC)
        token = await RefreshToken.create(
            token_hash="s" * 64,
            jti="jti-refresh-2",
            user_id="42",
            expires_at=now + timedelta(days=7),
        )
        assert token.is_valid is True

    async def test_is_expired(self):
        past = datetime(2020, 1, 1, tzinfo=UTC)
        token = await RefreshToken.create(
            token_hash="t" * 64,
            jti="jti-refresh-3",
            user_id="42",
            expires_at=past,
        )
        assert token.is_expired is True
        assert token.is_valid is False

    async def test_default_access_jti(self):
        now = datetime.now(tz=UTC)
        token = await RefreshToken.create(
            token_hash="u" * 64,
            jti="jti-refresh-4",
            user_id="42",
            expires_at=now + timedelta(days=7),
        )
        assert token.access_jti == ""

    async def test_repr(self):
        now = datetime.now(tz=UTC)
        token = await RefreshToken.create(
            token_hash="v" * 64,
            jti="jti-refresh-5",
            user_id="42",
            expires_at=now + timedelta(days=7),
        )
        assert "jti-refresh-5" in repr(token)
        assert "42" in repr(token)
