"""JWT token backend following the SimpleJWT approach."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
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
    """Stateless JWT token backend with optional blacklist for revocation."""

    def __init__(self, config: AuthConfig | None = None) -> None:
        self._config = config

    @property
    def config(self) -> AuthConfig:
        return self._config or get_config()

    @property
    def _secret(self) -> str:
        return self.config.jwt_secret or self.config.signing_secret

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair:
        """Create a JWT access/refresh token pair."""
        cfg = self.config
        now = time.time()
        now_int = int(now)

        access_jti = uuid.uuid4().hex
        access_payload: dict[str, Any] = {
            "sub": user_id,
            "token_type": "access",
            "jti": access_jti,
            "iat": now_int,
            "exp": now_int + cfg.access_token_lifetime,
        }
        if cfg.jwt_issuer:
            access_payload["iss"] = cfg.jwt_issuer
        if cfg.jwt_audience:
            access_payload["aud"] = cfg.jwt_audience
        if extra:
            access_payload["extra"] = extra

        refresh_jti = uuid.uuid4().hex
        refresh_payload: dict[str, Any] = {
            "sub": user_id,
            "token_type": "refresh",
            "jti": refresh_jti,
            "iat": now_int,
            "exp": now_int + cfg.refresh_token_lifetime,
        }
        if cfg.jwt_issuer:
            refresh_payload["iss"] = cfg.jwt_issuer
        if cfg.jwt_audience:
            refresh_payload["aud"] = cfg.jwt_audience

        access_token = jwt.encode(access_payload, self._secret, algorithm=cfg.jwt_algorithm)
        refresh_token = jwt.encode(refresh_payload, self._secret, algorithm=cfg.jwt_algorithm)

        if cfg.jwt_blacklist_enabled:
            from tortoise_auth.models.jwt_blacklist import OutstandingToken

            now_dt = datetime.fromtimestamp(now, tz=UTC)
            await OutstandingToken.bulk_create(
                [
                    OutstandingToken(
                        jti=access_jti,
                        user_id=user_id,
                        token_type="access",
                        created_at=now_dt,
                        expires_at=datetime.fromtimestamp(
                            now_int + cfg.access_token_lifetime, tz=UTC
                        ),
                    ),
                    OutstandingToken(
                        jti=refresh_jti,
                        user_id=user_id,
                        token_type="refresh",
                        created_at=now_dt,
                        expires_at=datetime.fromtimestamp(
                            now_int + cfg.refresh_token_lifetime, tz=UTC
                        ),
                    ),
                ]
            )

        return TokenPair(access_token=access_token, refresh_token=refresh_token)

    async def verify_token(self, token: str, *, token_type: str = "access") -> TokenPayload:
        """Decode and verify a JWT token."""
        if token_type not in ("access", "refresh"):
            raise TokenInvalidError(f"Unknown token type: {token_type!r}")

        decode_options: dict[str, Any] = {}
        decode_kwargs: dict[str, Any] = {
            "algorithms": [self.config.jwt_algorithm],
            "options": decode_options,
        }
        if self.config.jwt_issuer:
            decode_kwargs["issuer"] = self.config.jwt_issuer
        if self.config.jwt_audience:
            decode_kwargs["audience"] = self.config.jwt_audience
        else:
            decode_options["verify_aud"] = False

        try:
            payload = jwt.decode(token, self._secret, **decode_kwargs)
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except jwt.InvalidTokenError as exc:
            raise TokenInvalidError(f"Invalid token: {exc}") from exc

        if payload.get("token_type") != token_type:
            raise TokenInvalidError(
                f"Expected token type {token_type!r}, got {payload.get('token_type')!r}"
            )

        jti = payload.get("jti")
        if not jti:
            raise TokenInvalidError("Token missing jti claim")

        if self.config.jwt_blacklist_enabled:
            from tortoise_auth.models.jwt_blacklist import BlacklistedToken

            if await BlacklistedToken.filter(jti=jti).exists():
                raise TokenRevokedError("Token has been revoked")

        return TokenPayload(
            sub=payload["sub"],
            token_type=token_type,
            jti=jti,
            iat=payload["iat"],
            exp=payload["exp"],
            extra=payload.get("extra"),
        )

    async def revoke_token(self, token: str) -> None:
        """Revoke a JWT by adding its JTI to the blacklist."""
        if not self.config.jwt_blacklist_enabled:
            return

        payload = self._decode_unverified(token)
        if payload is None:
            return

        jti = payload.get("jti")
        if not jti:
            return

        from tortoise_auth.models.jwt_blacklist import BlacklistedToken

        if not await BlacklistedToken.filter(jti=jti).exists():
            await BlacklistedToken.create(jti=jti)

    async def revoke_all_for_user(self, user_id: str) -> None:
        """Revoke all tokens for a user by blacklisting their outstanding JTIs."""
        if not self.config.jwt_blacklist_enabled:
            return

        from tortoise_auth.models.jwt_blacklist import BlacklistedToken, OutstandingToken

        jtis = await OutstandingToken.filter(user_id=user_id).values_list("jti", flat=True)
        if not jtis:
            return

        existing = set(await BlacklistedToken.filter(jti__in=jtis).values_list("jti", flat=True))
        new_entries = [BlacklistedToken(jti=jti) for jti in jtis if jti not in existing]
        if new_entries:
            await BlacklistedToken.bulk_create(new_entries)

    async def cleanup_expired(self) -> int:
        """Delete expired outstanding tokens and their blacklist entries."""
        from tortoise_auth.models.jwt_blacklist import BlacklistedToken, OutstandingToken

        now = datetime.now(tz=UTC)
        expired_jtis = list(
            await OutstandingToken.filter(expires_at__lt=now).values_list("jti", flat=True)
        )
        if not expired_jtis:
            return 0
        blacklist_deleted = await BlacklistedToken.filter(jti__in=expired_jtis).delete()
        outstanding_deleted = await OutstandingToken.filter(expires_at__lt=now).delete()
        return outstanding_deleted + blacklist_deleted

    def _decode_unverified(self, token: str) -> dict[str, Any] | None:
        """Decode a JWT without verifying expiration (for revocation of expired tokens)."""
        try:
            return jwt.decode(
                token,
                self._secret,
                algorithms=[self.config.jwt_algorithm],
                options={"verify_exp": False, "verify_aud": False},
            )
        except jwt.InvalidTokenError:
            return None
