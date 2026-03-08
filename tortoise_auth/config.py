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

    # Token settings
    access_token_lifetime: int = 900  # 15 minutes
    refresh_token_lifetime: int = 604_800  # 7 days
    token_length: int = 64

    # Rate limiting
    rate_limit_max_attempts: int = 5
    rate_limit_window: int = 300  # 5 minutes
    rate_limit_lockout: int = 600  # 10 minutes

    # Password limits
    max_password_length: int = 4096

    # Signing (HMAC)
    signing_secret: str = ""
    signing_token_lifetime: int = 86_400  # 24 hours

    # JWT settings
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_blacklist_enabled: bool = False

    # Onboarding settings
    onboarding_session_lifetime: int = 3600
    onboarding_session_token_length: int = 64
    onboarding_require_totp: bool = False
    onboarding_max_verification_attempts: int = 5
    onboarding_verification_code_ttl: int = 600
    onboarding_invalidate_previous_sessions: bool = True

    def validate(self) -> None:
        """Validate config. Raises ConfigurationError."""
        if self.access_token_lifetime <= 0:
            raise ConfigurationError("access_token_lifetime must be positive")
        if self.refresh_token_lifetime <= 0:
            raise ConfigurationError("refresh_token_lifetime must be positive")
        if self.rate_limit_max_attempts <= 0:
            raise ConfigurationError("rate_limit_max_attempts must be positive")
        if self.rate_limit_window <= 0:
            raise ConfigurationError("rate_limit_window must be positive")
        if self.rate_limit_lockout <= 0:
            raise ConfigurationError("rate_limit_lockout must be positive")
        if self.onboarding_session_lifetime <= 0:
            raise ConfigurationError("onboarding_session_lifetime must be positive")
        if self.onboarding_session_token_length < 32:
            raise ConfigurationError("onboarding_session_token_length must be at least 32")
        if self.onboarding_max_verification_attempts <= 0:
            raise ConfigurationError("onboarding_max_verification_attempts must be positive")

    @property
    def effective_signing_secret(self) -> str:
        """Return signing_secret."""
        return self.signing_secret

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
