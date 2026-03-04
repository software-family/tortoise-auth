"""HMAC-SHA256 signing for URL-safe tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import time

from tortoise_auth.config import get_config
from tortoise_auth.exceptions import BadSignatureError, SignatureExpiredError


class Signer:
    """HMAC-SHA256 signer producing URL-safe signed tokens."""

    def __init__(self, secret: str = "", *, separator: str = ":") -> None:
        self._secret = secret
        self._separator = separator

    @property
    def secret(self) -> str:
        return self._secret or get_config().effective_signing_secret

    def sign(self, value: str) -> str:
        """Sign a value and return value:signature."""
        signature = self._make_signature(value)
        return f"{value}{self._separator}{signature}"

    def unsign(self, signed_value: str) -> str:
        """Verify and return the original value. Raises BadSignatureError."""
        if self._separator not in signed_value:
            raise BadSignatureError("No separator found in signed value")
        value, signature = signed_value.rsplit(self._separator, 1)
        expected = self._make_signature(value)
        if not hmac.compare_digest(signature, expected):
            raise BadSignatureError("Signature does not match")
        return value

    def _make_signature(self, value: str) -> str:
        """Create HMAC-SHA256 signature encoded as URL-safe base64."""
        digest = hmac.new(
            self.secret.encode("utf-8"),
            value.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class TimestampSigner(Signer):
    """Signer with embedded timestamp for expiration."""

    def sign_with_timestamp(self, value: str) -> str:
        """Sign a value with an embedded timestamp."""
        timestamp = (
            base64.urlsafe_b64encode(str(int(time.time())).encode("ascii"))
            .rstrip(b"=")
            .decode("ascii")
        )
        value_with_ts = f"{value}{self._separator}{timestamp}"
        return super().sign(value_with_ts)

    def unsign_with_timestamp(self, signed_value: str, *, max_age: int | None = None) -> str:
        """Verify signature and optionally check expiration."""
        value_with_ts = super().unsign(signed_value)
        if self._separator not in value_with_ts:
            raise BadSignatureError("No timestamp found in signed value")
        value, timestamp_b64 = value_with_ts.rsplit(self._separator, 1)
        try:
            # Re-pad base64
            padding = 4 - len(timestamp_b64) % 4
            if padding != 4:
                timestamp_b64 += "=" * padding
            timestamp = int(base64.urlsafe_b64decode(timestamp_b64).decode("ascii"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise BadSignatureError("Invalid timestamp in signed value") from exc
        if max_age is not None:
            age = int(time.time()) - timestamp
            if age > max_age:
                raise SignatureExpiredError(
                    f"Signature expired: age {age}s exceeds max_age {max_age}s"
                )
            if age < 0:
                raise SignatureExpiredError("Signature timestamp is in the future")
        return value


def make_token(value: str, secret: str = "") -> str:
    """Create a timestamped signed token."""
    signer = TimestampSigner(secret)
    return signer.sign_with_timestamp(value)


def verify_token(token: str, *, max_age: int | None = None, secret: str = "") -> str:
    """Verify a timestamped signed token and return the original value."""
    signer = TimestampSigner(secret)
    return signer.unsign_with_timestamp(token, max_age=max_age)
