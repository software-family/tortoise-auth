"""Password hashing utilities for tortoise-auth."""

from __future__ import annotations

from pwdlib import PasswordHash
from pwdlib.hashers import HasherProtocol
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

from tortoise_auth.hashers.argon2 import default_hasher as _argon2_default
from tortoise_auth.hashers.bcrypt import default_hasher as _bcrypt_default
from tortoise_auth.hashers.pbkdf2 import PBKDF2Hasher


def default_password_hash(
    *,
    argon2_time_cost: int = 3,
    argon2_memory_cost: int = 65536,
    argon2_parallelism: int = 4,
    bcrypt_rounds: int = 12,
    pbkdf2_iterations: int = 600_000,
) -> PasswordHash:
    """Create a PasswordHash with all supported hashers.

    Argon2 is the primary hasher; Bcrypt and PBKDF2 are kept for migration.
    """
    return PasswordHash([
        _argon2_default(
            time_cost=argon2_time_cost,
            memory_cost=argon2_memory_cost,
            parallelism=argon2_parallelism,
        ),
        _bcrypt_default(rounds=bcrypt_rounds),
        PBKDF2Hasher(iterations=pbkdf2_iterations),
    ])


def make_password(password: str) -> str:
    """Hash a password using the primary hasher (Argon2)."""
    return default_password_hash().hash(password)


def check_password(password: str, hashed: str) -> tuple[bool, str | None]:
    """Verify a password and return (valid, updated_hash).

    If the hash was made with a non-primary hasher or outdated params,
    ``updated_hash`` contains the re-hashed value for transparent migration.
    """
    return default_password_hash().verify_and_update(password, hashed)


__all__ = [
    "Argon2Hasher",
    "BcryptHasher",
    "HasherProtocol",
    "PBKDF2Hasher",
    "PasswordHash",
    "check_password",
    "default_password_hash",
    "make_password",
]
