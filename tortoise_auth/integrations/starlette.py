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

from tortoise_auth.exceptions import AuthenticationError, TokenError
from tortoise_auth.services import AuthService

__all__ = ["AnonymousUser", "TokenAuthBackend", "login_required", "require_auth"]


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

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, Any]:
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
