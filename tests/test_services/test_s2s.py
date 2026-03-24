"""Tests for S2SService."""

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.events import emitter
from tortoise_auth.exceptions import AuthenticationError, ConfigurationError
from tortoise_auth.services.s2s import S2SAuthResult, S2SService


def _s2s_config(**overrides: object) -> AuthConfig:
    defaults: dict[str, object] = {"s2s_enabled": True, "s2s_token_env_var": "S2S_AUTH_TOKEN"}
    defaults.update(overrides)
    return AuthConfig(**defaults)


@pytest.fixture(autouse=True)
def _clear_events():
    emitter.clear()
    yield
    emitter.clear()


@pytest.fixture(autouse=True)
def _clear_config():
    from tortoise_auth import config as cfg_mod

    cfg_mod._config = None
    yield
    cfg_mod._config = None


class TestS2SServiceAuthenticate:
    async def test_authenticate_success(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret-token")
        svc = S2SService(_s2s_config())
        result = await svc.authenticate("my-secret-token")
        assert isinstance(result, S2SAuthResult)
        assert result.service_name is None

    async def test_authenticate_invalid_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret-token")
        svc = S2SService(_s2s_config())
        with pytest.raises(AuthenticationError, match="Invalid S2S token"):
            await svc.authenticate("wrong-token")

    async def test_authenticate_empty_token(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret-token")
        svc = S2SService(_s2s_config())
        with pytest.raises(AuthenticationError, match="Invalid S2S token"):
            await svc.authenticate("")

    async def test_authenticate_s2s_not_enabled(self):
        svc = S2SService(AuthConfig(s2s_enabled=False))
        with pytest.raises(ConfigurationError, match="not enabled"):
            await svc.authenticate("any-token")

    async def test_authenticate_env_var_not_set(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("S2S_AUTH_TOKEN", raising=False)
        svc = S2SService(_s2s_config())
        with pytest.raises(ConfigurationError, match="not set or empty"):
            await svc.authenticate("any-token")

    async def test_authenticate_env_var_empty(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "")
        svc = S2SService(_s2s_config())
        with pytest.raises(ConfigurationError, match="not set or empty"):
            await svc.authenticate("any-token")

    async def test_authenticate_with_service_name(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret-token")
        svc = S2SService(_s2s_config())
        result = await svc.authenticate("my-secret-token", service_name="billing-service")
        assert result.service_name == "billing-service"


class TestS2SMultipleTokens:
    async def test_first_token_matches(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "token-a,token-b")
        svc = S2SService(_s2s_config())
        result = await svc.authenticate("token-a")
        assert isinstance(result, S2SAuthResult)

    async def test_second_token_matches(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "token-a,token-b")
        svc = S2SService(_s2s_config())
        result = await svc.authenticate("token-b")
        assert isinstance(result, S2SAuthResult)

    async def test_none_match(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "token-a,token-b")
        svc = S2SService(_s2s_config())
        with pytest.raises(AuthenticationError, match="Invalid S2S token"):
            await svc.authenticate("token-c")

    async def test_whitespace_handling(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", " token-a , token-b ")
        svc = S2SService(_s2s_config())
        result = await svc.authenticate("token-a")
        assert isinstance(result, S2SAuthResult)

    async def test_empty_segments_ignored(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "token-a,,token-b")
        svc = S2SService(_s2s_config())
        result = await svc.authenticate("token-b")
        assert isinstance(result, S2SAuthResult)


class TestS2SEvents:
    async def test_success_emits_event(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret-token")
        svc = S2SService(_s2s_config())
        events: list[dict[str, object]] = []

        @emitter.on("s2s_auth_success")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        await svc.authenticate("my-secret-token", service_name="billing")
        assert len(events) == 1
        assert events[0]["service_name"] == "billing"

    async def test_failure_emits_event(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("S2S_AUTH_TOKEN", "my-secret-token")
        svc = S2SService(_s2s_config())
        events: list[dict[str, object]] = []

        @emitter.on("s2s_auth_failed")
        async def handler(**kwargs: object) -> None:
            events.append(kwargs)

        with pytest.raises(AuthenticationError):
            await svc.authenticate("wrong-token", service_name="billing")
        assert len(events) == 1
        assert events[0]["service_name"] == "billing"


class TestS2SCustomEnvVar:
    async def test_custom_env_var_name(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MY_CUSTOM_TOKEN", "custom-secret")
        svc = S2SService(_s2s_config(s2s_token_env_var="MY_CUSTOM_TOKEN"))
        result = await svc.authenticate("custom-secret")
        assert isinstance(result, S2SAuthResult)

    async def test_default_env_var_name(self):
        cfg = AuthConfig()
        assert cfg.s2s_token_env_var == "S2S_AUTH_TOKEN"

    async def test_default_s2s_disabled(self):
        cfg = AuthConfig()
        assert cfg.s2s_enabled is False
