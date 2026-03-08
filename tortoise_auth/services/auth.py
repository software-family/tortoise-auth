"""Authentication service orchestrating login, logout, and token management."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from tortoise import Tortoise
from tortoise.timezone import now as tz_now
from tortoise.transactions import in_transaction

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import AuthenticationError, RateLimitError
from tortoise_auth.tokens import AuthResult, TokenBackend, TokenPair

if TYPE_CHECKING:
    from tortoise_auth.rate_limit import RateLimitBackend


# Pre-computed Argon2 hash of a dummy value, used to equalize timing
# when a user is not found (prevents user-enumeration via timing).
_DUMMY_HASH: str | None = None


class AuthService:
    """High-level authentication service."""

    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        backend: TokenBackend | None = None,
        rate_limiter: RateLimitBackend | None = None,
    ) -> None:
        self._config = config
        self._backend = backend
        self._rate_limiter = rate_limiter

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

    async def login(self, identifier: str, password: str, **extra_claims: Any) -> AuthResult:
        """Authenticate a user by email and password, returning tokens."""
        if self._rate_limiter is not None:
            result = await self._rate_limiter.check(identifier)
            if not result.allowed:
                await emit(
                    "rate_limit_exceeded",
                    identifier=identifier,
                    retry_after=result.retry_after,
                )
                raise RateLimitError(identifier, result.retry_after)

        user_model = self._resolve_user_model()
        user = await user_model.filter(email=identifier).first()

        if user is None:
            self._dummy_verify(password)
            if self._rate_limiter is not None:
                await self._rate_limiter.record(identifier)
            await emit("user_login_failed", identifier=identifier, reason="not_found")
            raise AuthenticationError("Invalid credentials")

        if not user.is_active:
            self._dummy_verify(password)
            if self._rate_limiter is not None:
                await self._rate_limiter.record(identifier)
            await emit("user_login_failed", identifier=identifier, reason="inactive")
            raise AuthenticationError("Invalid credentials")

        if not await user.check_password(password):
            if self._rate_limiter is not None:
                await self._rate_limiter.record(identifier)
            await emit("user_login_failed", identifier=identifier, reason="bad_password")
            raise AuthenticationError("Invalid credentials")

        if self._rate_limiter is not None:
            await self._rate_limiter.reset(identifier)

        user_id = str(user.pk)
        tokens = await self.backend.create_tokens(user_id, **extra_claims)

        user.last_login = tz_now()
        await user.save(update_fields=["last_login"])

        await emit("user_login", user)

        return AuthResult(
            user=user,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
        )

    async def authenticate(self, token: str) -> Any:
        """Verify an access token and return the corresponding user."""
        payload = await self.backend.verify_token(token, token_type="access")
        user_model = self._resolve_user_model()
        user = await user_model.filter(pk=payload.sub).first()
        if user is None:
            raise AuthenticationError("User not found")
        if not user.is_active:
            raise AuthenticationError("User is inactive")
        return user

    async def refresh(self, refresh_token: str) -> TokenPair:
        """Verify a refresh token and issue new tokens (atomic)."""
        async with in_transaction():
            payload = await self.backend.verify_token(refresh_token, token_type="refresh")
            await self.backend.revoke_token(refresh_token)
            return await self.backend.create_tokens(payload.sub)

    async def logout(self, token: str) -> None:
        """Revoke a single token."""
        # Try to extract user info for event before revoking
        try:
            payload = await self.backend.verify_token(token, token_type="access")
            user_model = self._resolve_user_model()
            user = await user_model.filter(pk=payload.sub).first()
            await self.backend.revoke_token(token)
            if user is not None:
                await emit("user_logout", user)
        except Exception:
            await self.backend.revoke_token(token)

    async def logout_all(self, user_id: str) -> None:
        """Revoke all tokens for a user."""
        await self.backend.revoke_all_for_user(user_id)
        try:
            user_model = self._resolve_user_model()
            user = await user_model.filter(pk=user_id).first()
            if user is not None:
                await emit("user_logout", user)
        except Exception:
            pass

    def _dummy_verify(self, password: str) -> None:
        """Verify password against a dummy hash to prevent timing-based user enumeration."""
        global _DUMMY_HASH
        ph = self.config.get_password_hash()
        if _DUMMY_HASH is None:
            _DUMMY_HASH = ph.hash("dummy-password-for-timing")
        with contextlib.suppress(Exception):
            ph.verify(password, _DUMMY_HASH)

    def _resolve_user_model(self) -> Any:
        """Resolve the user model class from Tortoise registry."""
        model_path = self.config.user_model
        if not model_path:
            raise AuthenticationError("user_model not configured — set it via AuthConfig")
        if "." not in model_path:
            raise AuthenticationError(f"Invalid user_model format: {model_path!r}")

        app_label, model_name = model_path.rsplit(".", 1)
        try:
            return Tortoise.apps[app_label][model_name]
        except KeyError:
            raise AuthenticationError(
                f"User model {model_path!r} not found in Tortoise registry"
            ) from None
