"""PasskeyService — orchestrates WebAuthn registration and authentication."""

from __future__ import annotations

import json
import secrets
import time
from base64 import urlsafe_b64encode
from typing import TYPE_CHECKING, Any

from tortoise import Tortoise
from tortoise.timezone import now as tz_now

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import (
    PasskeyAuthenticationError,
    PasskeyError,
    PasskeyRegistrationError,
)
from tortoise_auth.passkey.challenge import ChallengeBackend, ChallengeData
from tortoise_auth.tokens import AuthResult, TokenBackend

if TYPE_CHECKING:
    from tortoise_auth.models.passkey import PasskeyCredential


def _require_webauthn() -> None:
    """Raise a clear error if py_webauthn is not installed."""
    try:
        import webauthn  # noqa: F401
    except ImportError:
        raise PasskeyError(
            "webauthn is required for passkey support. "
            "Install it with: pip install tortoise-auth[passkey]"
        ) from None


class PasskeyService:
    """High-level service for WebAuthn passkey registration and authentication."""

    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        backend: TokenBackend | None = None,
        challenge_backend: ChallengeBackend | None = None,
    ) -> None:
        self._config = config
        self._backend = backend
        self._challenge_backend = challenge_backend

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    @property
    def backend(self) -> TokenBackend:
        if self._backend is not None:
            return self._backend
        from tortoise_auth.tokens.jwt import JWTBackend

        self._backend = JWTBackend(self.config)
        return self._backend

    @property
    def challenge_backend(self) -> ChallengeBackend:
        if self._challenge_backend is not None:
            return self._challenge_backend
        from tortoise_auth.passkey.challenge_memory import InMemoryChallengeBackend

        self._challenge_backend = InMemoryChallengeBackend(self.config)
        return self._challenge_backend

    def _rp_id(self, override: str) -> str:
        return override or self.config.passkey_rp_id

    def _rp_name(self, override: str) -> str:
        return override or self.config.passkey_rp_name

    def _origin(self, override: str | list[str]) -> str | list[str]:
        return override or self.config.passkey_origin

    async def begin_registration(
        self,
        user: Any,
        *,
        rp_id: str = "",
        rp_name: str = "",
        origin: str = "",
    ) -> dict[str, Any]:
        """Generate WebAuthn registration options for a user.

        Returns a dict with:
        - "options": JSON string of registration options for the browser
        - "challenge_id": The ID to pass back to complete_registration
        """
        _require_webauthn()
        import webauthn
        from webauthn.helpers.structs import (
            AttestationConveyancePreference,
            AuthenticatorAttachment,
            AuthenticatorSelectionCriteria,
            PublicKeyCredentialDescriptor,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        from tortoise_auth.models.passkey import PasskeyCredential

        effective_rp_id = self._rp_id(rp_id)
        effective_rp_name = self._rp_name(rp_name)

        if not effective_rp_id:
            raise PasskeyRegistrationError("passkey_rp_id must be configured or provided")
        if not effective_rp_name:
            raise PasskeyRegistrationError("passkey_rp_name must be configured or provided")

        # Build exclude list from existing credentials
        existing = await PasskeyCredential.filter(user_id=str(user.pk)).all()
        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=bytes(cred.credential_id),
                transports=json.loads(cred.transports) if cred.transports else None,
            )
            for cred in existing
        ]

        # Build authenticator selection
        uv_map = {
            "required": UserVerificationRequirement.REQUIRED,
            "preferred": UserVerificationRequirement.PREFERRED,
            "discouraged": UserVerificationRequirement.DISCOURAGED,
        }
        uv = uv_map[self.config.passkey_user_verification]

        attachment_map: dict[str, AuthenticatorAttachment | None] = {
            "": None,
            "platform": AuthenticatorAttachment.PLATFORM,
            "cross-platform": AuthenticatorAttachment.CROSS_PLATFORM,
        }
        attachment = attachment_map[self.config.passkey_authenticator_attachment]

        if attachment:
            authenticator_selection = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=uv,
                authenticator_attachment=attachment,
            )
        else:
            authenticator_selection = AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=uv,
            )

        attestation_map = {
            "none": AttestationConveyancePreference.NONE,
            "indirect": AttestationConveyancePreference.INDIRECT,
            "direct": AttestationConveyancePreference.DIRECT,
            "enterprise": AttestationConveyancePreference.ENTERPRISE,
        }
        attestation = attestation_map[self.config.passkey_attestation]

        user_id_bytes = str(user.pk).encode()
        user_name = getattr(user, "email", str(user.pk))
        user_display_name = getattr(user, "display_name", user_name)

        options = webauthn.generate_registration_options(
            rp_id=effective_rp_id,
            rp_name=effective_rp_name,
            user_name=user_name,
            user_id=user_id_bytes,
            user_display_name=user_display_name,
            attestation=attestation,
            authenticator_selection=authenticator_selection,
            exclude_credentials=exclude_credentials,
        )

        # Store challenge
        challenge_id = secrets.token_urlsafe(32)
        challenge_data = ChallengeData(
            challenge=options.challenge,
            user_id=str(user.pk),
            created_at=time.monotonic(),
        )
        await self.challenge_backend.store(challenge_id, challenge_data)

        return {
            "options": webauthn.options_to_json(options),
            "challenge_id": challenge_id,
        }

    async def complete_registration(
        self,
        user: Any,
        *,
        credential: dict[str, Any] | str,
        challenge_id: str,
        rp_id: str = "",
        origin: str | list[str] = "",
        name: str = "",
    ) -> PasskeyCredential:
        """Verify and store a WebAuthn registration response.

        Returns the created PasskeyCredential model instance.
        """
        _require_webauthn()
        import webauthn

        from tortoise_auth.models.passkey import PasskeyCredential

        effective_rp_id = self._rp_id(rp_id)
        effective_origin = self._origin(origin)

        if not effective_rp_id:
            raise PasskeyRegistrationError("passkey_rp_id must be configured or provided")
        if not effective_origin:
            raise PasskeyRegistrationError("passkey_origin must be configured or provided")

        # Retrieve and consume challenge
        challenge_data = await self.challenge_backend.retrieve(challenge_id)
        await self.challenge_backend.delete(challenge_id)

        if challenge_data is None:
            await emit(
                "passkey_registration_failed", user=user, reason="challenge_expired_or_not_found"
            )
            raise PasskeyRegistrationError("Challenge expired or not found")

        if challenge_data.user_id != str(user.pk):
            await emit("passkey_registration_failed", user=user, reason="challenge_user_mismatch")
            raise PasskeyRegistrationError("Challenge does not belong to this user")

        # Parse credential if JSON string
        cred_dict: dict[str, Any] = (
            json.loads(credential) if isinstance(credential, str) else credential
        )

        try:
            verification = webauthn.verify_registration_response(
                credential=cred_dict,
                expected_challenge=challenge_data.challenge,
                expected_rp_id=effective_rp_id,
                expected_origin=effective_origin,
                require_user_verification=(self.config.passkey_user_verification == "required"),
            )
        except Exception as exc:
            await emit("passkey_registration_failed", user=user, reason=str(exc))
            raise PasskeyRegistrationError(f"Registration verification failed: {exc}") from exc

        credential_id_bytes = verification.credential_id
        credential_id_b64 = urlsafe_b64encode(credential_id_bytes).rstrip(b"=").decode()

        # Extract transports from the credential response
        transports_list = cred_dict.get("response", {}).get("transports", [])
        if not transports_list:
            transports_list = cred_dict.get("transports", [])

        passkey = await PasskeyCredential.create(
            user_id=str(user.pk),
            credential_id=credential_id_bytes,
            credential_id_b64=credential_id_b64,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=verification.aaguid,
            credential_device_type=verification.credential_device_type,
            credential_backed_up=verification.credential_backed_up,
            name=name,
            transports=json.dumps(transports_list) if transports_list else "",
        )

        await emit("passkey_registered", user=user, credential=passkey)
        return passkey

    async def begin_authentication(
        self,
        *,
        rp_id: str = "",
        user: Any | None = None,
    ) -> dict[str, Any]:
        """Generate WebAuthn authentication options.

        If user is provided, limits allowed_credentials to that user's credentials.
        If user is None, allows discoverable credentials (passkey-first flow).

        Returns a dict with "options" (JSON string) and "challenge_id".
        """
        _require_webauthn()
        import webauthn
        from webauthn.helpers.structs import (
            PublicKeyCredentialDescriptor,
            UserVerificationRequirement,
        )

        from tortoise_auth.models.passkey import PasskeyCredential

        effective_rp_id = self._rp_id(rp_id)
        if not effective_rp_id:
            raise PasskeyAuthenticationError("passkey_rp_id must be configured or provided")

        uv_map = {
            "required": UserVerificationRequirement.REQUIRED,
            "preferred": UserVerificationRequirement.PREFERRED,
            "discouraged": UserVerificationRequirement.DISCOURAGED,
        }
        uv = uv_map[self.config.passkey_user_verification]

        allow_credentials: list[PublicKeyCredentialDescriptor] | None = None
        user_id_str: str | None = None
        if user is not None:
            user_id_str = str(user.pk)
            existing = await PasskeyCredential.filter(user_id=user_id_str).all()
            allow_credentials = [
                PublicKeyCredentialDescriptor(
                    id=bytes(cred.credential_id),
                    transports=json.loads(cred.transports) if cred.transports else None,
                )
                for cred in existing
            ]

        kwargs: dict[str, Any] = {
            "rp_id": effective_rp_id,
            "user_verification": uv,
        }
        if allow_credentials is not None:
            kwargs["allow_credentials"] = allow_credentials
        options = webauthn.generate_authentication_options(**kwargs)

        challenge_id = secrets.token_urlsafe(32)
        challenge_data = ChallengeData(
            challenge=options.challenge,
            user_id=user_id_str,
            created_at=time.monotonic(),
        )
        await self.challenge_backend.store(challenge_id, challenge_data)

        return {
            "options": webauthn.options_to_json(options),
            "challenge_id": challenge_id,
        }

    async def complete_authentication(
        self,
        *,
        credential: dict[str, Any] | str,
        challenge_id: str,
        rp_id: str = "",
        origin: str | list[str] = "",
        **extra_claims: Any,
    ) -> AuthResult:
        """Verify a WebAuthn authentication response and issue tokens.

        Returns AuthResult with user and token pair.
        """
        _require_webauthn()
        import webauthn

        from tortoise_auth.models.passkey import PasskeyCredential

        effective_rp_id = self._rp_id(rp_id)
        effective_origin = self._origin(origin)

        if not effective_rp_id:
            raise PasskeyAuthenticationError("passkey_rp_id must be configured or provided")
        if not effective_origin:
            raise PasskeyAuthenticationError("passkey_origin must be configured or provided")

        # Retrieve and consume challenge
        challenge_data = await self.challenge_backend.retrieve(challenge_id)
        await self.challenge_backend.delete(challenge_id)

        if challenge_data is None:
            await emit(
                "passkey_authentication_failed",
                credential_id=None,
                reason="challenge_expired_or_not_found",
            )
            raise PasskeyAuthenticationError("Challenge expired or not found")

        # Parse credential if JSON string
        cred_dict: dict[str, Any] = (
            json.loads(credential) if isinstance(credential, str) else credential
        )

        # Look up the stored credential by ID
        raw_id = cred_dict.get("rawId") or cred_dict.get("id", "")
        # Normalize base64url: strip padding
        raw_id_b64 = raw_id.rstrip("=")

        stored = await PasskeyCredential.filter(credential_id_b64=raw_id_b64).first()
        if stored is None:
            await emit(
                "passkey_authentication_failed",
                credential_id=raw_id_b64,
                reason="credential_not_found",
            )
            raise PasskeyAuthenticationError("Unknown credential")

        try:
            verification = webauthn.verify_authentication_response(
                credential=cred_dict,
                expected_challenge=challenge_data.challenge,
                expected_rp_id=effective_rp_id,
                expected_origin=effective_origin,
                credential_public_key=bytes(stored.public_key),
                credential_current_sign_count=stored.sign_count,
                require_user_verification=(self.config.passkey_user_verification == "required"),
            )
        except Exception as exc:
            await emit(
                "passkey_authentication_failed",
                credential_id=raw_id_b64,
                reason=str(exc),
            )
            raise PasskeyAuthenticationError(f"Authentication verification failed: {exc}") from exc

        # Update credential state
        stored.sign_count = verification.new_sign_count
        stored.last_used_at = tz_now()
        await stored.save(update_fields=["sign_count", "last_used_at"])

        # Resolve user and check active
        user_model = self._resolve_user_model()
        user = await user_model.filter(pk=stored.user_id).first()
        if user is None:
            raise PasskeyAuthenticationError("User not found")
        if not user.is_active:
            raise PasskeyAuthenticationError("User is inactive")

        # Issue tokens
        tokens = await self.backend.create_tokens(str(user.pk), **extra_claims)

        user.last_login = tz_now()
        await user.save(update_fields=["last_login"])

        await emit("passkey_authenticated", user=user, credential=stored)

        return AuthResult(
            user=user,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
        )

    async def list_credentials(self, user: Any) -> list[PasskeyCredential]:
        """List all passkey credentials for a user."""
        from tortoise_auth.models.passkey import PasskeyCredential

        return await PasskeyCredential.filter(user_id=str(user.pk)).all()

    async def delete_credential(
        self,
        user: Any,
        credential_id_b64: str,
    ) -> None:
        """Delete a passkey credential belonging to a user.

        Args:
            user: The user who owns the credential.
            credential_id_b64: The base64url-encoded credential ID.
        """
        from tortoise_auth.models.passkey import PasskeyCredential

        stored = await PasskeyCredential.filter(
            credential_id_b64=credential_id_b64,
            user_id=str(user.pk),
        ).first()

        if stored is None:
            raise PasskeyError("Credential not found or does not belong to this user")

        await stored.delete()
        await emit("passkey_deleted", user=user, credential_id=credential_id_b64)

    def _resolve_user_model(self) -> Any:
        """Resolve the user model class from Tortoise registry."""
        model_path = self.config.user_model
        if not model_path:
            raise PasskeyError("user_model not configured — set it via AuthConfig")
        if "." not in model_path:
            raise PasskeyError(f"Invalid user_model format: {model_path!r}")

        app_label, model_name = model_path.rsplit(".", 1)
        try:
            return Tortoise.apps[app_label][model_name]
        except KeyError:
            raise PasskeyError(
                f"User model {model_path!r} not found in Tortoise registry"
            ) from None
