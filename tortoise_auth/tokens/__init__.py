"""Token backends and data types for tortoise-auth."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class TokenPair:
    """A pair of access and refresh tokens."""

    access_token: str
    refresh_token: str


@dataclass(frozen=True, slots=True)
class AuthResult:
    """Result of a successful authentication containing user and tokens."""

    user: Any
    access_token: str
    refresh_token: str

    @property
    def tokens(self) -> TokenPair:
        return TokenPair(access_token=self.access_token, refresh_token=self.refresh_token)


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """Decoded token payload."""

    sub: str  # user_id as string
    token_type: str  # "access" or "refresh"
    jti: str  # unique token id
    iat: int  # issued-at epoch
    exp: int  # expiration epoch
    extra: dict[str, Any] | None = None


@runtime_checkable
class TokenBackend(Protocol):
    """Protocol for token backends."""

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair: ...
    async def verify_token(self, token: str, *, token_type: str = "access") -> TokenPayload: ...
    async def revoke_token(self, token: str) -> None: ...
    async def revoke_all_for_user(self, user_id: str) -> None: ...
