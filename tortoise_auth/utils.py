"""Utility functions for tortoise-auth."""

import hmac
import secrets
import string

UNUSABLE_PASSWORD_PREFIX = "!"
UNUSABLE_PASSWORD_SUFFIX_LENGTH = 40


def generate_random_string(
    length: int,
    alphabet: str = string.ascii_letters + string.digits,
) -> str:
    """Generate a cryptographically secure random string."""
    return "".join(secrets.choice(alphabet) for _ in range(length))


def constant_time_compare(val1: str | bytes, val2: str | bytes) -> bool:
    """Compare two values in constant time to prevent timing attacks."""
    if isinstance(val1, str):
        val1 = val1.encode("utf-8")
    if isinstance(val2, str):
        val2 = val2.encode("utf-8")
    return hmac.compare_digest(val1, val2)


def make_unusable_password() -> str:
    """Return a password hash that will never be accepted."""
    return UNUSABLE_PASSWORD_PREFIX + generate_random_string(UNUSABLE_PASSWORD_SUFFIX_LENGTH)


def is_password_usable(encoded: str | None) -> bool:
    """Check if a password hash represents a usable password."""
    return bool(encoded) and not encoded.startswith(UNUSABLE_PASSWORD_PREFIX)  # type: ignore[union-attr]
