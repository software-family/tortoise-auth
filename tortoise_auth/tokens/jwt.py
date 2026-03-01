"""JWT token backend using PyJWT."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt

from tortoise_auth.config import AuthConfig, get_config
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)
from tortoise_auth.tokens import TokenPair, TokenPayload


class JWTBackend:
    """JWT-based token backend with in-memory revocation."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config
        self._revoked_jtis: set[str] = set()

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair:
        """Create an access/refresh token pair."""
        now = int(time.time())
        cfg = self.config
        access = self._encode(
            sub=user_id,
            token_type="access",
            now=now,
            lifetime=cfg.jwt_access_token_lifetime,
            extra=extra or None,
        )
        refresh = self._encode(
            sub=user_id,
            token_type="refresh",
            now=now,
            lifetime=cfg.jwt_refresh_token_lifetime,
            extra=None,
        )
        return TokenPair(access_token=access, refresh_token=refresh)

    async def verify_token(
        self, token: str, *, token_type: str = "access"
    ) -> TokenPayload:
        """Decode and verify a JWT token."""
        cfg = self.config
        try:
            decode_key = cfg.jwt_public_key if cfg.jwt_public_key else cfg.jwt_secret
            kwargs: dict[str, Any] = {"algorithms": [cfg.jwt_algorithm]}
            if cfg.jwt_issuer:
                kwargs["issuer"] = cfg.jwt_issuer
            if cfg.jwt_audience:
                kwargs["audience"] = cfg.jwt_audience
            else:
                kwargs["options"] = {"verify_aud": False}

            payload = jwt.decode(token, decode_key, **kwargs)
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenInvalidError(f"Invalid token: {exc}") from exc

        actual_type = payload.get("type", "")
        if actual_type != token_type:
            raise TokenInvalidError(
                f"Expected token type {token_type!r}, got {actual_type!r}"
            )

        jti = payload.get("jti", "")
        if jti in self._revoked_jtis:
            raise TokenRevokedError("Token has been revoked")

        return TokenPayload(
            sub=payload["sub"],
            token_type=actual_type,
            jti=jti,
            iat=payload.get("iat", 0),
            exp=payload.get("exp", 0),
            extra=payload.get("extra"),
        )

    async def revoke_token(self, token: str) -> None:
        """Revoke a token by adding its jti to the in-memory blacklist."""
        try:
            cfg = self.config
            decode_key = cfg.jwt_public_key if cfg.jwt_public_key else cfg.jwt_secret
            payload = jwt.decode(
                token,
                decode_key,
                algorithms=[cfg.jwt_algorithm],
                options={"verify_exp": False, "verify_aud": False},
            )
            jti = payload.get("jti", "")
            if jti:
                self._revoked_jtis.add(jti)
        except jwt.InvalidTokenError:
            pass  # Already invalid, nothing to revoke

    async def revoke_all_for_user(self, user_id: str) -> None:
        """No-op for JWT backend — cannot revoke all without token list."""

    def _encode(
        self,
        *,
        sub: str,
        token_type: str,
        now: int,
        lifetime: int,
        extra: dict[str, Any] | None,
    ) -> str:
        """Encode a JWT token."""
        cfg = self.config
        payload: dict[str, Any] = {
            "sub": sub,
            "type": token_type,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + lifetime,
        }
        if cfg.jwt_issuer:
            payload["iss"] = cfg.jwt_issuer
        if cfg.jwt_audience:
            payload["aud"] = cfg.jwt_audience
        if extra:
            payload["extra"] = extra
        return jwt.encode(payload, cfg.jwt_secret, algorithm=cfg.jwt_algorithm)
