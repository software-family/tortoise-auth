"""Tests for the InvitationService."""

import time

import pytest

from tortoise_auth.config import AuthConfig, ConfigurationError
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    BadSignatureError,
    InvitationAlreadyAcceptedError,
    InvitationError,
    InvitationExpiredError,
    InvitationNotFoundError,
    InvitationRevokedError,
    SignatureExpiredError,
)
from tortoise_auth.models.invitation import Invitation
from tortoise_auth.services.invitation import InvitationService


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        signing_secret="test-signing-secret-that-is-at-least-32-bytes!",
        jwt_secret="test-jwt-secret-key-that-is-at-least-32-bytes!",
        invitation_require=True,
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


class TestCreateInvitation:
    async def test_returns_token_string(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com", invited_by="1")
        assert isinstance(token, str)
        assert len(token) > 0

    async def test_creates_invitation_record(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("admin@example.com")

        invitations = await Invitation.all()
        assert len(invitations) == 1
        assert invitations[0].email == "admin@example.com"
        assert invitations[0].accepted_at is None
        assert invitations[0].revoked_at is None

    async def test_stores_invited_by_and_role(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("admin@example.com", invited_by="42", role="editor")

        inv = await Invitation.first()
        assert inv.invited_by == "42"
        assert inv.role == "editor"

    async def test_emits_invitation_created_event(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        events: list[dict[str, object]] = []

        @emitter.on("invitation_created")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        token = await svc.create_invitation("admin@example.com", invited_by="1", role="admin")

        assert len(events) == 1
        assert events[0]["email"] == "admin@example.com"
        assert events[0]["token"] == token
        assert events[0]["invited_by"] == "1"
        assert events[0]["role"] == "admin"

    async def test_max_pending_enforced(self):
        cfg = make_config(invitation_max_pending=1)
        svc = InvitationService(cfg)

        await svc.create_invitation("admin@example.com")

        with pytest.raises(InvitationError, match="Maximum pending"):
            await svc.create_invitation("admin@example.com")

    async def test_max_pending_allows_different_emails(self):
        cfg = make_config(invitation_max_pending=1)
        svc = InvitationService(cfg)

        await svc.create_invitation("admin1@example.com")
        # Different email should be fine
        token = await svc.create_invitation("admin2@example.com")
        assert isinstance(token, str)

    async def test_max_pending_unlimited_by_default(self):
        cfg = make_config(invitation_max_pending=0)
        svc = InvitationService(cfg)

        for i in range(5):
            await svc.create_invitation(f"admin{i}@example.com")

        assert await Invitation.all().count() == 5


class TestValidateInvitation:
    async def test_valid_token_returns_invitation(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")

        invitation = await svc.validate_invitation(token)
        assert invitation.email == "admin@example.com"
        assert invitation.is_valid

    async def test_expired_token_raises(self):
        cfg = make_config(invitation_token_lifetime=1)
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")

        time.sleep(2)

        with pytest.raises(SignatureExpiredError):
            await svc.validate_invitation(token)

    async def test_tampered_token_raises(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        with pytest.raises(BadSignatureError):
            await svc.validate_invitation("totally-invalid-token")

    async def test_already_accepted_raises(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")

        await svc.accept_invitation(token)

        with pytest.raises(InvitationAlreadyAcceptedError):
            await svc.validate_invitation(token)

    async def test_revoked_raises(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")

        inv = await Invitation.first()
        await svc.revoke_invitation(inv.id)

        with pytest.raises(InvitationRevokedError):
            await svc.validate_invitation(token)

    async def test_not_found_raises(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        # Create a cryptographically valid token that's not in the DB
        from tortoise_auth.signing import make_token

        fake_token = make_token("nobody@example.com", cfg.effective_signing_secret)

        with pytest.raises(InvitationNotFoundError):
            await svc.validate_invitation(fake_token)


class TestAcceptInvitation:
    async def test_marks_accepted_at(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")

        invitation = await svc.accept_invitation(token)
        assert invitation.accepted_at is not None
        assert invitation.is_accepted

    async def test_emits_invitation_accepted_event(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")
        events: list[dict[str, object]] = []

        @emitter.on("invitation_accepted")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.accept_invitation(token)

        assert len(events) == 1
        assert events[0]["email"] == "admin@example.com"

    async def test_double_accept_raises(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("admin@example.com")

        await svc.accept_invitation(token)

        with pytest.raises(InvitationAlreadyAcceptedError):
            await svc.accept_invitation(token)


class TestRevokeInvitation:
    async def test_marks_revoked_at(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("admin@example.com")
        inv = await Invitation.first()

        await svc.revoke_invitation(inv.id)

        inv = await Invitation.get(id=inv.id)
        assert inv.is_revoked
        assert inv.revoked_at is not None

    async def test_emits_invitation_revoked_event(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("admin@example.com")
        inv = await Invitation.first()
        events: list[dict[str, object]] = []

        @emitter.on("invitation_revoked")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.revoke_invitation(inv.id)

        assert len(events) == 1
        assert events[0]["email"] == "admin@example.com"

    async def test_revoke_nonexistent_raises(self):
        cfg = make_config()
        svc = InvitationService(cfg)

        with pytest.raises(InvitationNotFoundError):
            await svc.revoke_invitation(99999)


class TestListPending:
    async def test_returns_pending_invitations(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("a@example.com")
        await svc.create_invitation("b@example.com")

        pending = await svc.list_pending()
        assert len(pending) == 2

    async def test_filters_by_email(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("a@example.com")
        await svc.create_invitation("b@example.com")

        pending = await svc.list_pending(email="a@example.com")
        assert len(pending) == 1
        assert pending[0].email == "a@example.com"

    async def test_excludes_accepted(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        token = await svc.create_invitation("a@example.com")
        await svc.accept_invitation(token)

        pending = await svc.list_pending()
        assert len(pending) == 0

    async def test_excludes_revoked(self):
        cfg = make_config()
        svc = InvitationService(cfg)
        await svc.create_invitation("a@example.com")
        inv = await Invitation.first()
        await svc.revoke_invitation(inv.id)

        pending = await svc.list_pending()
        assert len(pending) == 0


class TestCleanupExpired:
    async def test_deletes_expired_invitations(self):
        cfg = make_config(invitation_token_lifetime=1)
        svc = InvitationService(cfg)
        await svc.create_invitation("a@example.com")

        time.sleep(2)

        deleted = await svc.cleanup_expired()
        assert deleted == 1
        assert await Invitation.all().count() == 0


class TestInvitationConfig:
    def test_rejects_invalid_token_lifetime(self):
        cfg = AuthConfig(invitation_token_lifetime=0)
        with pytest.raises(ConfigurationError, match="invitation_token_lifetime"):
            cfg.validate()

    def test_accepts_valid_config(self):
        cfg = AuthConfig(invitation_token_lifetime=3600, invitation_require=True)
        cfg.validate()  # Should not raise