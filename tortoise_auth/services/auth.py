"""Authentication service orchestrating login, logout, and token management."""

from __future__ import annotations

from typing import Any

from tortoise import Tortoise
from tortoise.timezone import now as tz_now

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import AuthenticationError
from tortoise_auth.tokens import AuthResult, TokenBackend, TokenPair


class AuthService:
    """High-level authentication service."""

    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        backend: TokenBackend | None = None,
    ) -> None:
        self._config = config
        self._backend = backend

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    @property
    def backend(self) -> TokenBackend:
        if self._backend is not None:
            return self._backend
        cfg = self.config
        if cfg.token_backend == "database":
            from tortoise_auth.tokens.database import DatabaseTokenBackend

            return DatabaseTokenBackend(cfg)
        from tortoise_auth.tokens.jwt import JWTBackend

        return JWTBackend(cfg)

    async def login(
        self, identifier: str, password: str, **extra_claims: Any
    ) -> AuthResult:
        """Authenticate a user by email and password, returning tokens."""
        user_model = self._resolve_user_model()
        user = await user_model.filter(email=identifier).first()

        if user is None:
            await emit("user_login_failed", identifier=identifier, reason="not_found")
            raise AuthenticationError("Invalid credentials")

        if not user.is_active:
            await emit("user_login_failed", identifier=identifier, reason="inactive")
            raise AuthenticationError("Invalid credentials")

        if not await user.check_password(password):
            await emit("user_login_failed", identifier=identifier, reason="bad_password")
            raise AuthenticationError("Invalid credentials")

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
        """Verify a refresh token and issue new tokens."""
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

    def _resolve_user_model(self) -> Any:
        """Resolve the user model class from Tortoise registry."""
        model_path = self.config.user_model
        if not model_path:
            raise AuthenticationError(
                "user_model not configured — set it via AuthConfig"
            )
        if "." not in model_path:
            raise AuthenticationError(f"Invalid user_model format: {model_path!r}")

        app_label, model_name = model_path.rsplit(".", 1)
        try:
            return Tortoise.apps[app_label][model_name]
        except KeyError:
            raise AuthenticationError(
                f"User model {model_path!r} not found in Tortoise registry"
            ) from None
