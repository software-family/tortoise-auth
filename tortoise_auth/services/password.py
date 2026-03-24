"""Password reset service for tortoise-auth."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tortoise import Tortoise

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import PasswordResetError, RateLimitError
from tortoise_auth.signing import make_token, verify_token
from tortoise_auth.validators import validate_password

if TYPE_CHECKING:
    from tortoise_auth.rate_limit import RateLimitBackend
    from tortoise_auth.tokens import TokenBackend


class PasswordResetService:
    """High-level password reset service."""

    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        rate_limiter: RateLimitBackend | None = None,
        token_backend: TokenBackend | None = None,
    ) -> None:
        self._config = config
        self._rate_limiter = rate_limiter
        self._token_backend = token_backend

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def request_reset(self, email: str) -> None:
        """Request a password reset for the given email.

        Always returns None to avoid revealing whether the email exists.
        """
        if self._rate_limiter is not None:
            result = await self._rate_limiter.check(email)
            if not result.allowed:
                await emit(
                    "rate_limit_exceeded",
                    identifier=email,
                    retry_after=result.retry_after,
                )
                raise RateLimitError(email, result.retry_after)

        user_model = self._resolve_user_model()
        user = await user_model.filter(email=email).first()

        if user is not None and user.is_active:
            token = make_token(str(user.pk), self.config.effective_signing_secret)
            await emit("password_reset_requested", email=email, token=token, user=user)

        if self._rate_limiter is not None:
            await self._rate_limiter.record(email)

    async def confirm_reset(self, token: str, new_password: str) -> None:
        """Confirm a password reset using a signed token and new password."""
        user_pk = verify_token(
            token,
            max_age=self.config.password_reset_token_lifetime,
            secret=self.config.effective_signing_secret,
        )

        user_model = self._resolve_user_model()
        user = await user_model.filter(pk=user_pk).first()

        if user is None:
            raise PasswordResetError("User not found")

        if not user.is_active:
            raise PasswordResetError("User is inactive")

        validate_password(new_password, user=user)
        await user.set_password(new_password)

        if self._token_backend is not None:
            await self._token_backend.revoke_all_for_user(str(user.pk))

        await emit("password_reset_completed", user=user)

    def _resolve_user_model(self) -> Any:
        """Resolve the user model class from Tortoise registry."""
        model_path = self.config.user_model
        if not model_path:
            raise PasswordResetError("user_model not configured — set it via AuthConfig")
        if "." not in model_path:
            raise PasswordResetError(f"Invalid user_model format: {model_path!r}")

        app_label, model_name = model_path.rsplit(".", 1)
        try:
            return Tortoise.apps[app_label][model_name]
        except KeyError:
            raise PasswordResetError(
                f"User model {model_path!r} not found in Tortoise registry"
            ) from None
