"""Starlette integration for tortoise-auth.

Provides ``AuthenticationMiddleware``-compatible backend and route helpers
so that ``request.user`` is automatically populated from a Bearer token.

Usage::

    from starlette.applications import Starlette
    from starlette.middleware.authentication import AuthenticationMiddleware
    from tortoise_auth.integrations.starlette import TokenAuthBackend

    app = Starlette(...)
    app.add_middleware(AuthenticationMiddleware, backend=TokenAuthBackend())
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any

from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.responses import JSONResponse, RedirectResponse, Response

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import HTTPConnection, Request

    from tortoise_auth.rate_limit import RateLimitBackend

from tortoise_auth.exceptions import AuthenticationError, ConfigurationError, TokenError
from tortoise_auth.services import AuthService
from tortoise_auth.services.s2s import S2SService

__all__ = [
    "AnonymousUser",
    "RateLimitMiddleware",
    "S2SAuthBackend",
    "ServiceIdentity",
    "TokenAuthBackend",
    "login_required",
    "require_auth",
    "require_s2s",
]


class AnonymousUser:
    """Unauthenticated user placeholder.

    Compatible with Starlette's ``BaseUser`` protocol and
    ``AbstractUser``'s boolean properties.
    """

    @property
    def is_authenticated(self) -> bool:
        return False

    @property
    def is_anonymous(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return ""


class TokenAuthBackend(AuthenticationBackend):
    """Bearer-token authentication backend for Starlette's ``AuthenticationMiddleware``."""

    def __init__(
        self,
        auth_service: AuthService | None = None,
        *,
        scopes: tuple[str, ...] = ("authenticated",),
    ) -> None:
        self._auth_service = auth_service
        self._scopes = scopes

    @property
    def auth_service(self) -> AuthService:
        if self._auth_service is None:
            self._auth_service = AuthService()
        return self._auth_service

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, Any]:
        anonymous = (AuthCredentials([]), AnonymousUser())

        authorization = conn.headers.get("Authorization")
        if not authorization:
            return anonymous

        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return anonymous

        token = parts[1]
        try:
            user = await self.auth_service.authenticate(token)
        except (TokenError, AuthenticationError):
            return anonymous

        return AuthCredentials(list(self._scopes)), user


def require_auth(request: Request) -> Any:
    """Extract the authenticated user from a request or raise ``AuthenticationError``.

    This is a synchronous helper intended for use inside route handlers::

        async def my_route(request: Request) -> Response:
            user = require_auth(request)
            return JSONResponse({"email": user.email})
    """
    if not request.user.is_authenticated:
        raise AuthenticationError("Authentication required")
    return request.user


def login_required(
    fn: Callable[..., Any] | None = None,
    *,
    status_code: int = 401,
    redirect_url: str | None = None,
) -> Any:
    """Decorator that rejects unauthenticated requests.

    Supports usage with and without parentheses::

        @login_required
        async def view(request): ...


        @login_required(status_code=403)
        async def admin_view(request): ...


        @login_required(redirect_url="/login")
        async def html_view(request): ...
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Response:
            if not request.user.is_authenticated:
                if redirect_url is not None:
                    return RedirectResponse(url=redirect_url, status_code=302)
                return JSONResponse(
                    {"detail": "Authentication required"},
                    status_code=status_code,
                )
            return await func(request, *args, **kwargs)  # type: ignore[no-any-return]

        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator


class RateLimitMiddleware:
    """ASGI middleware for IP-based rate limiting on specific paths."""

    def __init__(
        self,
        app: Any,
        rate_limiter: RateLimitBackend,
        *,
        paths: list[str] | None = None,
    ) -> None:
        self.app = app
        self.rate_limiter = rate_limiter
        self.paths = paths

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if self.paths is not None and scope["path"] not in self.paths:
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        ip = client[0] if client else "unknown"

        result = await self.rate_limiter.check(ip)
        if not result.allowed:
            response = JSONResponse(
                {"detail": "Too many requests", "retry_after": result.retry_after},
                status_code=429,
                headers={"Retry-After": str(result.retry_after)},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


class ServiceIdentity:
    """Authenticated service placeholder for S2S requests.

    Compatible with Starlette's ``BaseUser`` protocol.
    """

    def __init__(self, service_name: str | None = None) -> None:
        self._service_name = service_name

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def is_anonymous(self) -> bool:
        return False

    @property
    def display_name(self) -> str:
        return self._service_name or "service"

    @property
    def service_name(self) -> str | None:
        return self._service_name


class S2SAuthBackend(AuthenticationBackend):
    """Bearer-token S2S authentication backend for Starlette's ``AuthenticationMiddleware``."""

    def __init__(
        self,
        s2s_service: S2SService | None = None,
        *,
        scopes: tuple[str, ...] = ("authenticated", "s2s"),
        service_name_header: str | None = "X-Service-Name",
    ) -> None:
        self._s2s_service = s2s_service
        self._scopes = scopes
        self._service_name_header = service_name_header

    @property
    def s2s_service(self) -> S2SService:
        if self._s2s_service is None:
            self._s2s_service = S2SService()
        return self._s2s_service

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, Any]:
        anonymous = (AuthCredentials([]), AnonymousUser())

        authorization = conn.headers.get("Authorization")
        if not authorization:
            return anonymous

        parts = authorization.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return anonymous

        token = parts[1]
        service_name: str | None = None
        if self._service_name_header:
            service_name = conn.headers.get(self._service_name_header)

        try:
            result = await self.s2s_service.authenticate(token, service_name=service_name)
        except (AuthenticationError, ConfigurationError):
            return anonymous

        return AuthCredentials(list(self._scopes)), ServiceIdentity(result.service_name)


def require_s2s(request: Request) -> ServiceIdentity:
    """Extract the authenticated service identity or raise ``AuthenticationError``.

    Use this in route handlers that require S2S authentication::

        async def internal_route(request: Request) -> Response:
            svc = require_s2s(request)
            return JSONResponse({"service": svc.display_name})
    """
    if not request.user.is_authenticated or not isinstance(request.user, ServiceIdentity):
        raise AuthenticationError("S2S authentication required")
    return request.user
