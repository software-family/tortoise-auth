"""Tests for AuthConfig validation."""

import pytest

from tortoise_auth.config import AuthConfig
from tortoise_auth.exceptions import ConfigurationError


class TestAuthConfigValidation:
    def test_default_config_is_valid(self):
        cfg = AuthConfig()
        cfg.validate()  # Should not raise

    def test_rejects_non_positive_access_token_lifetime(self):
        cfg = AuthConfig(access_token_lifetime=0)
        with pytest.raises(ConfigurationError, match="access_token_lifetime"):
            cfg.validate()

    def test_rejects_negative_access_token_lifetime(self):
        cfg = AuthConfig(access_token_lifetime=-1)
        with pytest.raises(ConfigurationError, match="access_token_lifetime"):
            cfg.validate()

    def test_rejects_non_positive_refresh_token_lifetime(self):
        cfg = AuthConfig(refresh_token_lifetime=0)
        with pytest.raises(ConfigurationError, match="refresh_token_lifetime"):
            cfg.validate()


class TestAuthConfigJWTDefaults:
    def test_jwt_secret_default(self):
        cfg = AuthConfig()
        assert cfg.jwt_secret == ""

    def test_jwt_algorithm_default(self):
        cfg = AuthConfig()
        assert cfg.jwt_algorithm == "HS256"

    def test_jwt_issuer_default(self):
        cfg = AuthConfig()
        assert cfg.jwt_issuer == ""

    def test_jwt_audience_default(self):
        cfg = AuthConfig()
        assert cfg.jwt_audience == ""

    def test_jwt_blacklist_enabled_default(self):
        cfg = AuthConfig()
        assert cfg.jwt_blacklist_enabled is False

    def test_jwt_fields_can_be_set(self):
        cfg = AuthConfig(
            jwt_secret="secret",
            jwt_algorithm="HS384",
            jwt_issuer="myapp",
            jwt_audience="myapi",
            jwt_blacklist_enabled=True,
        )
        assert cfg.jwt_secret == "secret"
        assert cfg.jwt_algorithm == "HS384"
        assert cfg.jwt_issuer == "myapp"
        assert cfg.jwt_audience == "myapi"
        assert cfg.jwt_blacklist_enabled is True
