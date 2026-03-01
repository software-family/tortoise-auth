"""Global configuration for tortoise-auth."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tortoise_auth.exceptions import ConfigurationError
from tortoise_auth.hashers import default_password_hash
from tortoise_auth.validators.common import CommonPasswordValidator
from tortoise_auth.validators.length import MinimumLengthValidator
from tortoise_auth.validators.numeric import NumericPasswordValidator
from tortoise_auth.validators.similarity import UserAttributeSimilarityValidator

if TYPE_CHECKING:
    from pwdlib import PasswordHash

    from tortoise_auth.validators import PasswordValidator


def _default_validators() -> list[PasswordValidator]:
    return [
        MinimumLengthValidator(),
        CommonPasswordValidator(),
        NumericPasswordValidator(),
        UserAttributeSimilarityValidator(),
    ]


@dataclass
class AuthConfig:
    """Configuration for tortoise-auth."""

    user_model: str = ""

    # Hasher parameters
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4
    bcrypt_rounds: int = 12
    pbkdf2_iterations: int = 600_000

    # Validators
    password_validators: list[PasswordValidator] = field(default_factory=_default_validators)

    # JWT settings
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_public_key: str = ""
    jwt_access_token_lifetime: int = 900  # 15 minutes
    jwt_refresh_token_lifetime: int = 604_800  # 7 days
    jwt_issuer: str = ""
    jwt_audience: str = ""

    # Token backend
    token_backend: str = "jwt"  # "jwt" or "database"

    # Database tokens
    db_token_length: int = 64

    # Signing (HMAC)
    signing_secret: str = ""
    signing_token_lifetime: int = 86_400  # 24 hours

    def validate(self) -> None:
        """Validate config. Raises ConfigurationError."""
        if self.token_backend == "jwt" and not self.jwt_secret:
            raise ConfigurationError("jwt_secret required for JWT backend")
        if self.jwt_algorithm.startswith("RS") and not self.jwt_public_key:
            raise ConfigurationError("jwt_public_key required for RS256")

    @property
    def effective_signing_secret(self) -> str:
        """Return signing_secret if set, otherwise fall back to jwt_secret."""
        return self.signing_secret or self.jwt_secret

    def get_password_hash(self) -> PasswordHash:
        """Build a PasswordHash instance from current config."""
        return default_password_hash(
            argon2_time_cost=self.argon2_time_cost,
            argon2_memory_cost=self.argon2_memory_cost,
            argon2_parallelism=self.argon2_parallelism,
            bcrypt_rounds=self.bcrypt_rounds,
            pbkdf2_iterations=self.pbkdf2_iterations,
        )


_config: AuthConfig | None = None


def configure(config: AuthConfig) -> None:
    """Set the global auth configuration."""
    global _config
    _config = config


def get_config() -> AuthConfig:
    """Get the global auth configuration, creating a default if needed."""
    global _config
    if _config is None:
        _config = AuthConfig()
    return _config
