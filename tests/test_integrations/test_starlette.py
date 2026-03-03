"""Tests for the Starlette integration."""

import pytest
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from tests.models import MinimalUser
from tortoise_auth.config import AuthConfig
from tortoise_auth.exceptions import AuthenticationError
from tortoise_auth.integrations.starlette import (
    AnonymousUser,
    TokenAuthBackend,
    login_required,
    require_auth,
)
from tortoise_auth.services.auth import AuthService


def make_config(**overrides: object) -> AuthConfig:
    return AuthConfig(
        user_model="models.MinimalUser",
        access_token_lifetime=900,
        refresh_token_lifetime=604_800,
        jwt_secret="test-secret-key-that-is-at-least-32-bytes!",
        jwt_blacklist_enabled=True,
        **overrides,
    )


async def _create_user(
    email: str = "user@example.com", password: str = "Str0ngP@ss!"
) -> MinimalUser:
    user = await MinimalUser.create(email=email)
    await user.set_password(password)
    return user


def make_app(backend: TokenAuthBackend | None = None) -> Starlette:
    """Minimal Starlette app with AuthenticationMiddleware for testing."""

    async def user_info(request: Request) -> JSONResponse:
        return JSONResponse({
            "is_authenticated": request.user.is_authenticated,
            "is_anonymous": request.user.is_anonymous,
            "scopes": list(request.auth.scopes),
        })

    async def protected(request: Request) -> JSONResponse:
        return JSONResponse({"email": request.user.email})

    @login_required
    async def decorated_no_parens(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    @login_required()
    async def decorated_with_parens(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    @login_required(status_code=403)
    async def decorated_403(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    @login_required(redirect_url="/login")
    async def decorated_redirect(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def require_auth_route(request: Request) -> JSONResponse:
        user = require_auth(request)
        return JSONResponse({"email": user.email})

    app = Starlette(
        routes=[
            Route("/user-info", user_info),
            Route("/protected", protected),
            Route("/decorated-no-parens", decorated_no_parens),
            Route("/decorated-with-parens", decorated_with_parens),
            Route("/decorated-403", decorated_403),
            Route("/decorated-redirect", decorated_redirect),
            Route("/require-auth", require_auth_route),
        ],
    )
    if backend is None:
        backend = TokenAuthBackend()
    app.add_middleware(AuthenticationMiddleware, backend=backend)
    return app


class TestAnonymousUser:
    def test_is_authenticated_is_false(self):
        user = AnonymousUser()
        assert user.is_authenticated is False

    def test_is_anonymous_is_true(self):
        user = AnonymousUser()
        assert user.is_anonymous is True

    def test_display_name_is_empty(self):
        user = AnonymousUser()
        assert user.display_name == ""


class TestTokenAuthBackend:
    async def test_authenticated_request(self):
        user = await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")

        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get(
            "/user-info",
            headers={"Authorization": f"Bearer {result.access_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_authenticated"] is True
        assert data["is_anonymous"] is False
        assert "authenticated" in data["scopes"]

    async def test_missing_header(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get("/user-info")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_authenticated"] is False

    async def test_invalid_token(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get(
            "/user-info",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_authenticated"] is False

    async def test_non_bearer_scheme(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get(
            "/user-info",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_authenticated"] is False

    async def test_custom_scopes(self):
        user = await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")

        backend = TokenAuthBackend(auth_service=svc, scopes=("admin", "write"))
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get(
            "/user-info",
            headers={"Authorization": f"Bearer {result.access_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert set(data["scopes"]) == {"admin", "write"}


class TestLoginRequired:
    async def test_authenticated_passes_through(self):
        user = await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")

        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get(
            "/decorated-no-parens",
            headers={"Authorization": f"Bearer {result.access_token}"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    async def test_unauthenticated_returns_401(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get("/decorated-no-parens")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Authentication required"}

    async def test_custom_status_code_403(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get("/decorated-403")
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Authentication required"}

    async def test_redirect_url(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app, follow_redirects=False)

        resp = client.get("/decorated-redirect")
        assert resp.status_code == 302
        assert resp.headers["location"] == "/login"

    async def test_works_with_parentheses(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get("/decorated-with-parens")
        assert resp.status_code == 401

    async def test_works_without_parentheses(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get("/decorated-no-parens")
        assert resp.status_code == 401


class TestRequireAuth:
    async def test_returns_user_when_authenticated(self):
        user = await _create_user()
        cfg = make_config()
        svc = AuthService(cfg)
        result = await svc.login("user@example.com", "Str0ngP@ss!")

        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app)

        resp = client.get(
            "/require-auth",
            headers={"Authorization": f"Bearer {result.access_token}"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"email": "user@example.com"}

    async def test_raises_when_unauthenticated(self):
        cfg = make_config()
        svc = AuthService(cfg)
        backend = TokenAuthBackend(auth_service=svc)
        app = make_app(backend=backend)
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/require-auth")
        assert resp.status_code == 500
