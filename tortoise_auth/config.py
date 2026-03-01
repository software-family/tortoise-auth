"""Global configuration for tortoise-auth."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

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
