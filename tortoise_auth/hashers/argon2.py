"""Argon2 password hasher (wraps pwdlib)."""

from pwdlib.hashers.argon2 import Argon2Hasher


def default_hasher(
    *,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4,
) -> Argon2Hasher:
    """Create an Argon2Hasher with OWASP-recommended defaults."""
    return Argon2Hasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    )


__all__ = ["Argon2Hasher", "default_hasher"]
