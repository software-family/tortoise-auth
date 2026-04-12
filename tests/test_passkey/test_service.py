"""Tests for the PasskeyService."""

from __future__ import annotations

import json
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tests.models import MinimalUser
from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import (
    PasskeyAuthenticationError,
    PasskeyError,
    PasskeyRegistrationError,
)
from tortoise_auth.models.passkey import PasskeyCredential
from tortoise_auth.passkey.challenge import ChallengeData
from tortoise_auth.passkey.challenge_memory import InMemoryChallengeBackend
from tortoise_auth.passkey.service import PasskeyService
from tortoise_auth.tokens import AuthResult
from tortoise_auth.tokens.jwt import JWTBackend


def make_config(**overrides: object) -> AuthConfig:
    defaults: dict[str, object] = {
        "user_model": "models.MinimalUser",
        "jwt_secret": "test-secret-key-that-is-at-least-32-bytes!",
        "jwt_blacklist_enabled": True,
        "passkey_rp_id": "example.com",
        "passkey_rp_name": "Test App",
        "passkey_origin": "https://example.com",
        "passkey_challenge_ttl": 300,
    }
    defaults.update(overrides)
    return AuthConfig(**defaults)  # type: ignore[arg-type]


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


# -- Mock helpers --

FAKE_CREDENTIAL_ID = b"\x01\x02\x03\x04\x05\x06\x07\x08"
FAKE_CREDENTIAL_ID_B64 = urlsafe_b64encode(FAKE_CREDENTIAL_ID).rstrip(b"=").decode()
FAKE_PUBLIC_KEY = b"\x10\x20\x30\x40\x50"
FAKE_AAGUID = "00000000-0000-0000-0000-000000000000"


@dataclass
class FakeVerifiedRegistration:
    credential_id: bytes = FAKE_CREDENTIAL_ID
    credential_public_key: bytes = FAKE_PUBLIC_KEY
    sign_count: int = 0
    aaguid: str = FAKE_AAGUID
    fmt: str = "none"
    credential_type: str = "public-key"
    user_verified: bool = True
    attestation_object: bytes = b""
    credential_device_type: str = "multi_device"
    credential_backed_up: bool = True


@dataclass
class FakeVerifiedAuthentication:
    credential_id: bytes = FAKE_CREDENTIAL_ID
    new_sign_count: int = 1
    credential_device_type: str = "multi_device"
    credential_backed_up: bool = True
    user_verified: bool = True


def _fake_registration_options() -> MagicMock:
    """Create a mock PublicKeyCredentialCreationOptions."""
    opts = MagicMock()
    opts.challenge = b"fake-challenge-bytes-registration"
    return opts


def _fake_authentication_options() -> MagicMock:
    """Create a mock PublicKeyCredentialRequestOptions."""
    opts = MagicMock()
    opts.challenge = b"fake-challenge-bytes-authentication"
    return opts


def _fake_credential_response() -> dict[str, Any]:
    """A minimal credential response dict as a browser would produce."""
    return {
        "id": FAKE_CREDENTIAL_ID_B64,
        "rawId": FAKE_CREDENTIAL_ID_B64,
        "type": "public-key",
        "response": {
            "attestationObject": "fake",
            "clientDataJSON": "fake",
        },
    }


def _fake_auth_credential_response() -> dict[str, Any]:
    return {
        "id": FAKE_CREDENTIAL_ID_B64,
        "rawId": FAKE_CREDENTIAL_ID_B64,
        "type": "public-key",
        "response": {
            "authenticatorData": "fake",
            "clientDataJSON": "fake",
            "signature": "fake",
        },
    }


class TestPasskeyRegistration:
    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{"mock": true}')
    async def test_begin_registration_returns_options(
        self, mock_to_json: MagicMock, mock_gen: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)
        result = await svc.begin_registration(user)
        assert "options" in result
        assert "challenge_id" in result
        assert result["options"] == '{"mock": true}'
        mock_gen.assert_called_once()

    @patch("webauthn.verify_registration_response")
    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_registration_stores_credential(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        mock_verify.return_value = FakeVerifiedRegistration()
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)

        reg = await svc.begin_registration(user)
        passkey = await svc.complete_registration(
            user,
            credential=_fake_credential_response(),
            challenge_id=reg["challenge_id"],
            name="My Key",
        )

        assert isinstance(passkey, PasskeyCredential)
        assert passkey.user_id == str(user.pk)
        assert passkey.credential_id_b64 == FAKE_CREDENTIAL_ID_B64
        assert bytes(passkey.public_key) == FAKE_PUBLIC_KEY
        assert passkey.sign_count == 0
        assert passkey.name == "My Key"
        assert passkey.credential_device_type == "multi_device"
        assert passkey.credential_backed_up is True

    @patch("webauthn.verify_registration_response")
    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_registration_emits_event(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        mock_verify.return_value = FakeVerifiedRegistration()
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)
        events: list[dict[str, Any]] = []

        @emitter.on("passkey_registered")
        async def handler(**kwargs: Any) -> None:
            events.append(kwargs)

        reg = await svc.begin_registration(user)
        await svc.complete_registration(
            user, credential=_fake_credential_response(), challenge_id=reg["challenge_id"]
        )
        assert len(events) == 1
        assert events[0]["user"].pk == user.pk

    async def test_complete_registration_expired_challenge(self):
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyRegistrationError, match="Challenge expired"):
            await svc.complete_registration(
                user,
                credential=_fake_credential_response(),
                challenge_id="nonexistent",
            )

    @patch("webauthn.verify_registration_response")
    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_registration_challenge_user_mismatch(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        user1 = await _create_user(email="user1@example.com")
        user2 = await _create_user(email="user2@example.com")
        cfg = make_config()
        svc = PasskeyService(cfg)

        reg = await svc.begin_registration(user1)
        with pytest.raises(PasskeyRegistrationError, match="does not belong"):
            await svc.complete_registration(
                user2,
                credential=_fake_credential_response(),
                challenge_id=reg["challenge_id"],
            )

    @patch("webauthn.verify_registration_response")
    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_registration_invalid_response(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        mock_verify.side_effect = Exception("Invalid attestation")
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)

        reg = await svc.begin_registration(user)
        with pytest.raises(PasskeyRegistrationError, match="verification failed"):
            await svc.complete_registration(
                user,
                credential=_fake_credential_response(),
                challenge_id=reg["challenge_id"],
            )

    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_begin_registration_excludes_existing(
        self, mock_to_json: MagicMock, mock_gen: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        user = await _create_user()

        # Create an existing credential
        await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=FAKE_CREDENTIAL_ID,
            credential_id_b64=FAKE_CREDENTIAL_ID_B64,
            public_key=FAKE_PUBLIC_KEY,
            sign_count=0,
        )

        cfg = make_config()
        svc = PasskeyService(cfg)
        await svc.begin_registration(user)

        call_kwargs = mock_gen.call_args[1]
        assert len(call_kwargs["exclude_credentials"]) == 1

    async def test_begin_registration_no_rp_id(self):
        user = await _create_user()
        cfg = make_config(passkey_rp_id="", passkey_rp_name="Test")
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyRegistrationError, match="rp_id"):
            await svc.begin_registration(user)

    async def test_begin_registration_no_rp_name(self):
        user = await _create_user()
        cfg = make_config(passkey_rp_id="example.com", passkey_rp_name="")
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyRegistrationError, match="rp_name"):
            await svc.begin_registration(user)

    @patch("webauthn.verify_registration_response")
    @patch("webauthn.generate_registration_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_registration_json_string_credential(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_registration_options()
        mock_verify.return_value = FakeVerifiedRegistration()
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)

        reg = await svc.begin_registration(user)
        passkey = await svc.complete_registration(
            user,
            credential=json.dumps(_fake_credential_response()),
            challenge_id=reg["challenge_id"],
        )
        assert isinstance(passkey, PasskeyCredential)


class TestPasskeyAuthentication:
    async def _setup_user_with_credential(self) -> tuple[MinimalUser, PasskeyCredential]:
        user = await _create_user()
        cred = await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=FAKE_CREDENTIAL_ID,
            credential_id_b64=FAKE_CREDENTIAL_ID_B64,
            public_key=FAKE_PUBLIC_KEY,
            sign_count=0,
            aaguid=FAKE_AAGUID,
            credential_device_type="multi_device",
            credential_backed_up=True,
        )
        return user, cred

    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{"mock": true}')
    async def test_begin_authentication_returns_options(
        self, mock_to_json: MagicMock, mock_gen: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        cfg = make_config()
        svc = PasskeyService(cfg)
        result = await svc.begin_authentication()
        assert "options" in result
        assert "challenge_id" in result

    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_begin_authentication_with_user_limits_credentials(
        self, mock_to_json: MagicMock, mock_gen: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        user, cred = await self._setup_user_with_credential()
        cfg = make_config()
        svc = PasskeyService(cfg)
        await svc.begin_authentication(user=user)

        call_kwargs = mock_gen.call_args[1]
        assert "allow_credentials" in call_kwargs
        assert len(call_kwargs["allow_credentials"]) == 1

    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_begin_authentication_without_user_discoverable(
        self, mock_to_json: MagicMock, mock_gen: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        cfg = make_config()
        svc = PasskeyService(cfg)
        await svc.begin_authentication()
        call_kwargs = mock_gen.call_args[1]
        assert "allow_credentials" not in call_kwargs

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_returns_auth_result(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.return_value = FakeVerifiedAuthentication()
        user, cred = await self._setup_user_with_credential()
        cfg = make_config()
        svc = PasskeyService(cfg)

        auth_opts = await svc.begin_authentication()
        result = await svc.complete_authentication(
            credential=_fake_auth_credential_response(),
            challenge_id=auth_opts["challenge_id"],
        )

        assert isinstance(result, AuthResult)
        assert result.user.pk == user.pk
        assert result.access_token
        assert result.refresh_token

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_updates_sign_count(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.return_value = FakeVerifiedAuthentication(new_sign_count=5)
        user, cred = await self._setup_user_with_credential()
        cfg = make_config()
        svc = PasskeyService(cfg)

        auth_opts = await svc.begin_authentication()
        await svc.complete_authentication(
            credential=_fake_auth_credential_response(),
            challenge_id=auth_opts["challenge_id"],
        )

        await cred.refresh_from_db()
        assert cred.sign_count == 5

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_updates_last_used(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.return_value = FakeVerifiedAuthentication()
        user, cred = await self._setup_user_with_credential()
        assert cred.last_used_at is None
        cfg = make_config()
        svc = PasskeyService(cfg)

        auth_opts = await svc.begin_authentication()
        await svc.complete_authentication(
            credential=_fake_auth_credential_response(),
            challenge_id=auth_opts["challenge_id"],
        )

        await cred.refresh_from_db()
        assert cred.last_used_at is not None

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_updates_last_login(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.return_value = FakeVerifiedAuthentication()
        user, cred = await self._setup_user_with_credential()
        assert user.last_login is None
        cfg = make_config()
        svc = PasskeyService(cfg)

        auth_opts = await svc.begin_authentication()
        await svc.complete_authentication(
            credential=_fake_auth_credential_response(),
            challenge_id=auth_opts["challenge_id"],
        )

        await user.refresh_from_db()
        assert user.last_login is not None

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_emits_event(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.return_value = FakeVerifiedAuthentication()
        user, cred = await self._setup_user_with_credential()
        cfg = make_config()
        svc = PasskeyService(cfg)
        events: list[dict[str, Any]] = []

        @emitter.on("passkey_authenticated")
        async def handler(**kwargs: Any) -> None:
            events.append(kwargs)

        auth_opts = await svc.begin_authentication()
        await svc.complete_authentication(
            credential=_fake_auth_credential_response(),
            challenge_id=auth_opts["challenge_id"],
        )

        assert len(events) == 1
        assert events[0]["user"].pk == user.pk

    async def test_complete_authentication_expired_challenge(self):
        cfg = make_config()
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyAuthenticationError, match="Challenge expired"):
            await svc.complete_authentication(
                credential=_fake_auth_credential_response(),
                challenge_id="nonexistent",
            )

    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_unknown_credential(
        self, mock_to_json: MagicMock, mock_gen: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        cfg = make_config()
        svc = PasskeyService(cfg)
        auth_opts = await svc.begin_authentication()
        with pytest.raises(PasskeyAuthenticationError, match="Unknown credential"):
            await svc.complete_authentication(
                credential=_fake_auth_credential_response(),
                challenge_id=auth_opts["challenge_id"],
            )

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_inactive_user(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.return_value = FakeVerifiedAuthentication()
        user, cred = await self._setup_user_with_credential()
        user.is_active = False
        await user.save(update_fields=["is_active"])
        cfg = make_config()
        svc = PasskeyService(cfg)

        auth_opts = await svc.begin_authentication()
        with pytest.raises(PasskeyAuthenticationError, match="inactive"):
            await svc.complete_authentication(
                credential=_fake_auth_credential_response(),
                challenge_id=auth_opts["challenge_id"],
            )

    @patch("webauthn.verify_authentication_response")
    @patch("webauthn.generate_authentication_options")
    @patch("webauthn.options_to_json", return_value='{}')
    async def test_complete_authentication_invalid_response(
        self, mock_to_json: MagicMock, mock_gen: MagicMock, mock_verify: MagicMock
    ):
        mock_gen.return_value = _fake_authentication_options()
        mock_verify.side_effect = Exception("Bad signature")
        user, cred = await self._setup_user_with_credential()
        cfg = make_config()
        svc = PasskeyService(cfg)

        auth_opts = await svc.begin_authentication()
        with pytest.raises(PasskeyAuthenticationError, match="verification failed"):
            await svc.complete_authentication(
                credential=_fake_auth_credential_response(),
                challenge_id=auth_opts["challenge_id"],
            )


class TestPasskeyCredentialManagement:
    async def test_list_credentials(self):
        user = await _create_user()
        await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=FAKE_CREDENTIAL_ID,
            credential_id_b64=FAKE_CREDENTIAL_ID_B64,
            public_key=FAKE_PUBLIC_KEY,
            sign_count=0,
        )
        cfg = make_config()
        svc = PasskeyService(cfg)
        creds = await svc.list_credentials(user)
        assert len(creds) == 1
        assert creds[0].credential_id_b64 == FAKE_CREDENTIAL_ID_B64

    async def test_list_credentials_empty(self):
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)
        creds = await svc.list_credentials(user)
        assert creds == []

    async def test_delete_credential(self):
        user = await _create_user()
        await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=FAKE_CREDENTIAL_ID,
            credential_id_b64=FAKE_CREDENTIAL_ID_B64,
            public_key=FAKE_PUBLIC_KEY,
            sign_count=0,
        )
        cfg = make_config()
        svc = PasskeyService(cfg)
        await svc.delete_credential(user, FAKE_CREDENTIAL_ID_B64)
        assert await PasskeyCredential.filter(user_id=str(user.pk)).count() == 0

    async def test_delete_credential_not_found(self):
        user = await _create_user()
        cfg = make_config()
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyError, match="not found"):
            await svc.delete_credential(user, "nonexistent")

    async def test_delete_credential_wrong_user(self):
        user1 = await _create_user(email="user1@example.com")
        user2 = await _create_user(email="user2@example.com")
        await PasskeyCredential.create(
            user_id=str(user1.pk),
            credential_id=FAKE_CREDENTIAL_ID,
            credential_id_b64=FAKE_CREDENTIAL_ID_B64,
            public_key=FAKE_PUBLIC_KEY,
            sign_count=0,
        )
        cfg = make_config()
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyError, match="not found"):
            await svc.delete_credential(user2, FAKE_CREDENTIAL_ID_B64)

    async def test_delete_emits_event(self):
        user = await _create_user()
        await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=FAKE_CREDENTIAL_ID,
            credential_id_b64=FAKE_CREDENTIAL_ID_B64,
            public_key=FAKE_PUBLIC_KEY,
            sign_count=0,
        )
        cfg = make_config()
        svc = PasskeyService(cfg)
        events: list[dict[str, Any]] = []

        @emitter.on("passkey_deleted")
        async def handler(**kwargs: Any) -> None:
            events.append(kwargs)

        await svc.delete_credential(user, FAKE_CREDENTIAL_ID_B64)
        assert len(events) == 1
        assert events[0]["credential_id"] == FAKE_CREDENTIAL_ID_B64


class TestPasskeyServiceConfig:
    async def test_no_user_model_configured(self):
        cfg = AuthConfig(passkey_rp_id="example.com")
        svc = PasskeyService(cfg)
        # _resolve_user_model is called in complete_authentication, so we test it directly
        with pytest.raises(PasskeyError, match="user_model not configured"):
            svc._resolve_user_model()

    def test_default_challenge_backend_is_memory(self):
        cfg = make_config()
        svc = PasskeyService(cfg)
        assert isinstance(svc.challenge_backend, InMemoryChallengeBackend)

    def test_explicit_challenge_backend(self):
        cfg = make_config()
        cb = InMemoryChallengeBackend(cfg)
        svc = PasskeyService(cfg, challenge_backend=cb)
        assert svc.challenge_backend is cb

    def test_default_backend_is_jwt(self):
        cfg = make_config()
        svc = PasskeyService(cfg)
        assert isinstance(svc.backend, JWTBackend)

    def test_explicit_backend(self):
        cfg = make_config()
        backend = JWTBackend(cfg)
        svc = PasskeyService(cfg, backend=backend)
        assert svc.backend is backend

    async def test_begin_authentication_no_rp_id(self):
        cfg = make_config(passkey_rp_id="")
        svc = PasskeyService(cfg)
        with pytest.raises(PasskeyAuthenticationError, match="rp_id"):
            await svc.begin_authentication()
