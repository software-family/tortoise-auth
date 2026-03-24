"""Async authentication and user management for Tortoise ORM."""

__version__ = "0.5.0"

from tortoise_auth.config import AuthConfig, configure, get_config
from tortoise_auth.events import emit, emitter, on
from tortoise_auth.exceptions import (
    AuthenticationError,
    BadSignatureError,
    ConfigurationError,
    EventError,
    InvalidHashError,
    InvalidPasswordError,
    OnboardingError,
    OnboardingFlowCompleteError,
    OnboardingSessionExpiredError,
    OnboardingSessionInvalidError,
    OnboardingStepError,
    PasswordResetError,
    RateLimitError,
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
    LoginAttempt,
    OnboardingSession,
    OutstandingToken,
    RefreshToken,
)
from tortoise_auth.onboarding import (
    ClientHint,
    FieldHint,
    OnboardingResult,
    OnboardingStep,
    OnboardingStepStatus,
    StepContext,
    StepResult,
)
from tortoise_auth.onboarding.flow import OnboardingFlow
from tortoise_auth.onboarding.service import OnboardingService
from tortoise_auth.onboarding.steps import (
    ProfileCompletionStep,
    RegisterStep,
    SetupTOTPStep,
    VerifyEmailStep,
)
from tortoise_auth.rate_limit import RateLimitBackend, RateLimitResult
from tortoise_auth.rate_limit.database import DatabaseRateLimitBackend
from tortoise_auth.rate_limit.memory import InMemoryRateLimitBackend
from tortoise_auth.services import AuthService, PasswordResetService, S2SAuthResult, S2SService
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
    "ClientHint",
    "ConfigurationError",
    "DatabaseRateLimitBackend",
    "DatabaseTokenBackend",
    "EventError",
    "FieldHint",
    "InMemoryRateLimitBackend",
    "InvalidHashError",
    "InvalidPasswordError",
    "JWTBackend",
    "LoginAttempt",
    "OnboardingError",
    "OnboardingFlow",
    "OnboardingFlowCompleteError",
    "OnboardingResult",
    "OnboardingService",
    "OnboardingSession",
    "OnboardingSessionExpiredError",
    "OnboardingSessionInvalidError",
    "OnboardingStep",
    "OnboardingStepError",
    "OnboardingStepStatus",
    "OutstandingToken",
    "PasswordResetError",
    "PasswordResetService",
    "ProfileCompletionStep",
    "RateLimitBackend",
    "RateLimitError",
    "RateLimitResult",
    "RefreshToken",
    "RegisterStep",
    "S2SAuthResult",
    "S2SService",
    "SetupTOTPStep",
    "SignatureExpiredError",
    "Signer",
    "SigningError",
    "StepContext",
    "StepResult",
    "TimestampSigner",
    "TokenBackend",
    "TokenError",
    "TokenExpiredError",
    "TokenInvalidError",
    "TokenPair",
    "TokenPayload",
    "TokenRevokedError",
    "TortoiseAuthError",
    "VerifyEmailStep",
    "configure",
    "emit",
    "emitter",
    "get_config",
    "make_token",
    "on",
    "verify_token",
]
