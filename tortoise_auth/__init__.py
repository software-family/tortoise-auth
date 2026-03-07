"""Async authentication and user management for Tortoise ORM."""

__version__ = "0.2.0"

from tortoise_auth.config import AuthConfig, configure, get_config
from tortoise_auth.events import emit, emitter, on
from tortoise_auth.exceptions import (
    AuthenticationError,
    BadSignatureError,
    ConfigurationError,
    EventError,
    InvalidHashError,
    InvalidPasswordError,
    SignatureExpiredError,
    SigningError,
    TokenError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    TortoiseAuthError,
)
from tortoise_auth.models import (
    AbstractUser,
    AccessToken,
    BlacklistedToken,
    OutstandingToken,
    RefreshToken,
)
from tortoise_auth.services import AuthService
from tortoise_auth.signing import Signer, TimestampSigner, make_token, verify_token
from tortoise_auth.tokens import AuthResult, TokenBackend, TokenPair, TokenPayload
from tortoise_auth.tokens.database import DatabaseTokenBackend
from tortoise_auth.tokens.jwt import JWTBackend

__all__ = [
    "AbstractUser",
    "AccessToken",
    "AuthConfig",
    "AuthResult",
    "AuthService",
    "AuthenticationError",
    "BadSignatureError",
    "BlacklistedToken",
    "ConfigurationError",
    "DatabaseTokenBackend",
    "EventError",
    "InvalidHashError",
    "InvalidPasswordError",
    "JWTBackend",
    "OutstandingToken",
    "RefreshToken",
    "SignatureExpiredError",
    "Signer",
    "SigningError",
    "TimestampSigner",
    "TokenBackend",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenPair",
    "TokenPayload",
    "TokenRevokedError",
    "TortoiseAuthError",
    "configure",
    "emit",
    "emitter",
    "get_config",
    "make_token",
    "on",
    "verify_token",
]
