"""Bcrypt password hasher (wraps pwdlib)."""

from pwdlib.hashers.bcrypt import BcryptHasher


def default_hasher(*, rounds: int = 12) -> BcryptHasher:
    """Create a BcryptHasher with OWASP-recommended defaults."""
    return BcryptHasher(rounds=rounds)


__all__ = ["BcryptHasher", "default_hasher"]
