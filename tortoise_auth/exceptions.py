"""Exception classes for tortoise-auth."""


class TortoiseAuthError(Exception):
    """Base exception for all tortoise-auth errors."""


class AuthenticationError(TortoiseAuthError):
    """Raised when authentication fails."""


class InvalidPasswordError(TortoiseAuthError):
    """Raised when password validation fails.

    Collects all validation errors before raising.
    """

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


class InvalidHashError(TortoiseAuthError):
    """Raised when a password hash is not recognized by any hasher."""

    def __init__(self, hash: str) -> None:
        self.hash = hash
        super().__init__(f"Unknown password hashing algorithm for hash: {hash!r}")


class ConfigurationError(TortoiseAuthError):
    """Raised when configuration is invalid."""


class EventError(TortoiseAuthError):
    """Raised when an event handler fails."""

    def __init__(self, event_name: str, handler_name: str, original: Exception) -> None:
        self.event_name = event_name
        self.handler_name = handler_name
        self.original = original
        super().__init__(
            f"Handler {handler_name!r} for event {event_name!r} "
            f"raised {type(original).__name__}: {original}"
        )


class TokenError(TortoiseAuthError):
    """Raised when a token operation fails."""


class TokenExpiredError(TokenError):
    """Raised when a token has expired."""


class TokenInvalidError(TokenError):
    """Raised when a token is structurally invalid or cannot be decoded."""


class TokenRevokedError(TokenError):
    """Raised when a revoked token is presented."""


class SigningError(TortoiseAuthError):
    """Raised when token signing or verification fails."""


class SignatureExpiredError(SigningError):
    """Raised when a signed token has expired."""


class BadSignatureError(SigningError):
    """Raised when a signed token has an invalid signature."""


class RateLimitError(TortoiseAuthError):
    """Raised when a login attempt is rejected due to rate limiting."""

    def __init__(self, identifier: str, retry_after: int) -> None:
        self.identifier = identifier
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded for {identifier!r}. Retry after {retry_after} seconds."
        )


class OnboardingError(TortoiseAuthError):
    """Base exception for onboarding flow errors."""


class OnboardingSessionExpiredError(OnboardingError):
    """Raised when an onboarding session has expired."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        super().__init__(f"Onboarding session {session_id!r} has expired")


class OnboardingSessionInvalidError(OnboardingError):
    """Raised when an onboarding session is not found or invalid."""

    def __init__(self, reason: str = "Session not found") -> None:
        self.reason = reason
        super().__init__(reason)


class OnboardingStepError(OnboardingError):
    """Raised when an onboarding step fails."""

    def __init__(self, step_name: str, errors: list[str]) -> None:
        self.step_name = step_name
        self.errors = errors
        super().__init__(f"Step {step_name!r} failed: {'; '.join(errors)}")


class OnboardingFlowCompleteError(OnboardingError):
    """Raised when attempting to advance a completed onboarding flow."""

    def __init__(self) -> None:
        super().__init__("Onboarding flow is already complete")
