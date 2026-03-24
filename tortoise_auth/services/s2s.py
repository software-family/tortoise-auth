"""Server-to-server authentication service for tortoise-auth."""

from __future__ import annotations

import os
from dataclasses import dataclass

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.events import emit
from tortoise_auth.exceptions import AuthenticationError, ConfigurationError
from tortoise_auth.utils import constant_time_compare


@dataclass(frozen=True, slots=True)
class S2SAuthResult:
    """Result of a successful S2S authentication."""

    service_name: str | None = None


class S2SService:
    """High-level service for server-to-server token authentication.

    Verifies bearer tokens against a value stored in an environment variable.
    Supports multiple comma-separated tokens for rotation.
    """

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def authenticate(
        self, token: str, *, service_name: str | None = None
    ) -> S2SAuthResult:
        """Verify an S2S bearer token against the configured environment variable.

        Args:
            token: The bearer token to verify.
            service_name: Optional service identifier for auditing.

        Returns:
            S2SAuthResult on success.

        Raises:
            ConfigurationError: If S2S auth is not enabled or env var is missing.
            AuthenticationError: If the token does not match.
        """
        if not self.config.s2s_enabled:
            raise ConfigurationError("S2S authentication is not enabled")

        valid_tokens = self._load_tokens()
        if not valid_tokens:
            raise ConfigurationError(
                f"S2S token environment variable {self.config.s2s_token_env_var!r} "
                f"is not set or empty"
            )

        for valid_token in valid_tokens:
            if constant_time_compare(token, valid_token):
                await emit("s2s_auth_success", service_name=service_name)
                return S2SAuthResult(service_name=service_name)

        await emit("s2s_auth_failed", service_name=service_name)
        raise AuthenticationError("Invalid S2S token")

    def _load_tokens(self) -> list[str]:
        """Load and parse tokens from the environment variable.

        Supports comma-separated values for token rotation.
        """
        raw = os.environ.get(self.config.s2s_token_env_var, "")
        if not raw:
            return []
        return [t.strip() for t in raw.split(",") if t.strip()]
