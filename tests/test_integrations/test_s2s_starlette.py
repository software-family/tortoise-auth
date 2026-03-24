"""Tests for S2S Starlette integration."""

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from tortoise_auth import AuthenticationError
from tortoise_auth.config import AuthConfig
from tortoise_auth.integrations.starlette import (
    S2SAuthBackend,
    ServiceIdentity,
    require_s2s,
)
from tortoise_auth.services.s2s import S2SService


def _s2s_config(**overrides: object) -> AuthConfig:
    return AuthConfig(s2s_enabled=True, s2s_token_env_var="S2S_AUTH_TOKEN", **overrides)


def _make_s2s_app(backend: S2SAuthBackend) -> Starlette:
    async def service_info(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "is_authenticated": request.user.is_authenticated,
                "is_anonymous": request.user.is_anonymous,
                "display_name": request.user.display_name,
                "scopes": list(request.auth.scopes),
            }
        )

    async def require_s2s_route(request: Request) -> JSONResponse:
        svc = require_s2s(request)
        return JSONResponse({"service": svc.display_name})

    app = Starlette(
        routes=[
            Route("/service-info", service_info),
            Route("/require-s2s", require_s2s_route),
        ],
    )
    app.add_middleware(AuthenticationMiddleware, backend=backend)
    return app


def _client(app: Starlette, **kwargs: object) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app, **kwargs),
        base_url="http://test",
    )


class TestServiceIdentity:
    def test_is_authenticated(self):
        si = ServiceIdentity()
        assert si.is_authenticated is True

    def test_is_anonymous(self):
        si = ServiceIdentity()
        assert si.is_anonymous is False

    def test_display_name_with_service_name(self):
        si = ServiceIdentity(service_name="billing")
        assert si.display_name == "billing"

    def test_display_name_without_service_name(self):
        si = ServiceIdentity()
        assert si.display_name == "service"

    def test_service_name_property(self):
        si = ServiceIdentity(service_name="billing")
        assert si.service_name == "billing"

    def test_service_name_none_by_default(self):
        si = ServiceIdentity()
        assert si.service_name is None


class TestS2SAuthBackend:
    async def test_valid_s2s_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={"Authorization": "Bearer my-secret"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_authenticated"] is True
        assert data["is_anonymous"] is False
        assert "authenticated" in data["scopes"]
        assert "s2s" in data["scopes"]

    async def test_invalid_s2s_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={"Authorization": "Bearer wrong-token"},
            )
        data = resp.json()
        assert data["is_authenticated"] is False

    async def test_missing_authorization_header(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get("/service-info")
        data = resp.json()
        assert data["is_authenticated"] is False

    async def test_non_bearer_scheme(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={"Authorization": "Basic dXNlcjpwYXNz"},
            )
        data = resp.json()
        assert data["is_authenticated"] is False

    async def test_custom_scopes(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc, scopes=("internal", "admin"))
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={"Authorization": "Bearer my-secret"},
            )
        data = resp.json()
        assert set(data["scopes"]) == {"internal", "admin"}

    async def test_service_name_from_header(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={
                    "Authorization": "Bearer my-secret",
                    "X-Service-Name": "billing",
                },
            )
        data = resp.json()
        assert data["display_name"] == "billing"

    async def test_no_service_name_header(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={"Authorization": "Bearer my-secret"},
            )
        data = resp.json()
        assert data["display_name"] == "service"

    async def test_disabled_service_name_header(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc, service_name_header=None)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/service-info",
                headers={
                    "Authorization": "Bearer my-secret",
                    "X-Service-Name": "billing",
                },
            )
        data = resp.json()
        assert data["display_name"] == "service"


class TestRequireS2S:
    async def test_returns_service_identity(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        async with _client(app) as client:
            resp = await client.get(
                "/require-s2s",
                headers={"Authorization": "Bearer my-secret"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"service": "service"}

    async def test_raises_when_anonymous(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret")
        svc = S2SService(_s2s_config())
        backend = S2SAuthBackend(s2s_service=svc)
        app = _make_s2s_app(backend)

        with pytest.raises(AuthenticationError, match="S2S authentication required"):
            async with _client(app, raise_app_exceptions=True) as client:
                await client.get("/require-s2s")
