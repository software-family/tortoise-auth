"""Tests for AbstractUser model."""

import pytest

from tortoise_auth.events import emitter
from tortoise_auth.hashers.argon2 import Argon2Hasher
from tortoise_auth.hashers.bcrypt import default_hasher as bcrypt_default

from tests.models import FullUser, MinimalUser


@pytest.fixture(autouse=True)
def _clear_events():
    emitter.clear()
    yield
    emitter.clear()


class TestAbstractUser:
    async def test_set_and_check_password(self):
        user = await MinimalUser.create(email="test@example.com")
        await user.set_password("secure_password_123")

        assert user.password != "secure_password_123"
        assert await user.check_password("secure_password_123")
        assert not await user.check_password("wrong")

    async def test_password_is_hashed_with_argon2(self):
        user = await MinimalUser.create(email="argon2@example.com")
        await user.set_password("test_password")
        assert Argon2Hasher.identify(user.password)

    async def test_unusable_password(self):
        user = await MinimalUser.create(email="unusable@example.com")
        user.set_unusable_password()

        assert not user.has_usable_password()
        assert not await user.check_password("anything")

    async def test_has_usable_password_after_set(self):
        user = await MinimalUser.create(email="usable@example.com")
        await user.set_password("real_password")
        assert user.has_usable_password()

    async def test_is_authenticated(self):
        user = await MinimalUser.create(email="auth@example.com")
        assert user.is_authenticated is True

    async def test_is_anonymous(self):
        user = await MinimalUser.create(email="anon@example.com")
        assert user.is_anonymous is False

    async def test_password_changed_event(self):
        events = []

        @emitter.on("password_changed")
        async def handler(u):
            events.append(u)

        user = await MinimalUser.create(email="event@example.com")
        await user.set_password("new_pass")

        assert len(events) == 1
        assert events[0].id == user.id

    async def test_password_saved_to_db(self):
        user = await MinimalUser.create(email="db@example.com")
        await user.set_password("db_password")

        reloaded = await MinimalUser.get(id=user.id)
        assert await reloaded.check_password("db_password")

    async def test_hash_migration_on_check(self):
        """Checking a bcrypt password should migrate it to argon2."""
        user = await MinimalUser.create(email="migrate@example.com")
        bcrypt_hasher = bcrypt_default(rounds=4)
        user.password = bcrypt_hasher.hash("migrate_me")
        await user.save(update_fields=["password"])

        assert not Argon2Hasher.identify(user.password)
        result = await user.check_password("migrate_me")
        assert result

        await user.refresh_from_db()
        assert Argon2Hasher.identify(user.password)

    async def test_empty_password_is_not_usable(self):
        user = await MinimalUser.create(email="empty@example.com")
        assert not user.has_usable_password()

    async def test_default_field_values(self):
        user = await MinimalUser.create(email="defaults@example.com")
        assert user.is_active is True
        assert user.is_verified is False
        assert user.created_at is not None

    async def test_repr(self):
        user = await MinimalUser.create(email="repr@example.com")
        assert repr(user) == "<MinimalUser: repr@example.com>"

    async def test_unique_email(self):
        await MinimalUser.create(email="same@example.com")
        from tortoise.exceptions import IntegrityError

        with pytest.raises(IntegrityError):
            await MinimalUser.create(email="same@example.com")

    async def test_custom_phone_field(self):
        user = await FullUser.create(email="phone@example.com", phone="+1234567890")
        assert user.phone == "+1234567890"
