"""PBKDF2-SHA256 password hasher (Django-compatible format)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os


_DEFAULT_ITERATIONS = 600_000


class PBKDF2Hasher:
    """PBKDF2-SHA256 hasher implementing pwdlib's HasherProtocol.

    Hash format: ``pbkdf2_sha256$iterations$salt_b64$hash_b64``
    """

    def __init__(self, iterations: int = _DEFAULT_ITERATIONS) -> None:
        self.iterations = iterations

    @classmethod
    def identify(cls, hash: str | bytes) -> bool:
        if isinstance(hash, bytes):
            hash = hash.decode("utf-8")
        return hash.startswith("pbkdf2_sha256$")

    def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
        if isinstance(password, str):
            password = password.encode("utf-8")
        if salt is None:
            salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password, salt, self.iterations)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(dk).decode("ascii")
        return f"pbkdf2_sha256${self.iterations}${salt_b64}${hash_b64}"

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        if isinstance(password, str):
            password = password.encode("utf-8")
        if isinstance(hash, bytes):
            hash = hash.decode("utf-8")
        parts = hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        stored_hash = base64.b64decode(parts[3])
        dk = hashlib.pbkdf2_hmac("sha256", password, salt, iterations)
        return hmac.compare_digest(dk, stored_hash)

    def check_needs_rehash(self, hash: str | bytes) -> bool:
        if isinstance(hash, bytes):
            hash = hash.decode("utf-8")
        parts = hash.split("$")
        if len(parts) != 4:
            return True
        return int(parts[1]) != self.iterations


__all__ = ["PBKDF2Hasher"]
