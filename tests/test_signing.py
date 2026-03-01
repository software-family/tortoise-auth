"""Tests for the HMAC signing module."""

import time
from unittest.mock import patch

import pytest

from tortoise_auth.exceptions import BadSignatureError, SignatureExpiredError
from tortoise_auth.signing import Signer, TimestampSigner, make_token, verify_token

SECRET = "test-secret-key-for-signing"


class TestSigner:
    def test_sign_and_unsign(self):
        signer = Signer(SECRET)
        signed = signer.sign("hello")
        assert signer.unsign(signed) == "hello"

    def test_sign_produces_separator(self):
        signer = Signer(SECRET)
        signed = signer.sign("value")
        assert ":" in signed
        assert signed.startswith("value:")

    def test_unsign_bad_signature(self):
        signer = Signer(SECRET)
        signed = signer.sign("hello")
        with pytest.raises(BadSignatureError):
            signer.unsign(signed + "tampered")

    def test_unsign_no_separator(self):
        signer = Signer(SECRET)
        with pytest.raises(BadSignatureError, match="No separator"):
            signer.unsign("noseparator")

    def test_unsign_wrong_secret(self):
        signer1 = Signer("secret-1")
        signer2 = Signer("secret-2")
        signed = signer1.sign("data")
        with pytest.raises(BadSignatureError):
            signer2.unsign(signed)

    def test_custom_separator(self):
        signer = Signer(SECRET, separator=".")
        signed = signer.sign("value")
        assert "." in signed
        assert ":" not in signed
        assert signer.unsign(signed) == "value"

    def test_sign_empty_value(self):
        signer = Signer(SECRET)
        signed = signer.sign("")
        assert signer.unsign(signed) == ""

    def test_sign_unicode_value(self):
        signer = Signer(SECRET)
        signed = signer.sign("héllo wörld")
        assert signer.unsign(signed) == "héllo wörld"

    def test_deterministic_signature(self):
        signer = Signer(SECRET)
        sig1 = signer.sign("same")
        sig2 = signer.sign("same")
        assert sig1 == sig2

    def test_different_values_different_signatures(self):
        signer = Signer(SECRET)
        sig1 = signer.sign("a")
        sig2 = signer.sign("b")
        assert sig1 != sig2


class TestTimestampSigner:
    def test_sign_and_unsign(self):
        signer = TimestampSigner(SECRET)
        signed = signer.sign_with_timestamp("hello")
        assert signer.unsign_with_timestamp(signed) == "hello"

    def test_unsign_with_max_age(self):
        signer = TimestampSigner(SECRET)
        signed = signer.sign_with_timestamp("hello")
        assert signer.unsign_with_timestamp(signed, max_age=60) == "hello"

    def test_expired_signature(self):
        signer = TimestampSigner(SECRET)
        with patch("tortoise_auth.signing.time.time", return_value=time.time() - 100):
            signed = signer.sign_with_timestamp("hello")
        with pytest.raises(SignatureExpiredError, match="exceeds max_age"):
            signer.unsign_with_timestamp(signed, max_age=10)

    def test_future_timestamp(self):
        signer = TimestampSigner(SECRET)
        with patch("tortoise_auth.signing.time.time", return_value=time.time() + 3600):
            signed = signer.sign_with_timestamp("hello")
        with pytest.raises(SignatureExpiredError, match="future"):
            signer.unsign_with_timestamp(signed, max_age=60)

    def test_no_max_age_no_expiry_check(self):
        signer = TimestampSigner(SECRET)
        with patch("tortoise_auth.signing.time.time", return_value=time.time() - 99999):
            signed = signer.sign_with_timestamp("hello")
        # No max_age means no expiration check
        assert signer.unsign_with_timestamp(signed) == "hello"

    def test_tampered_timestamp(self):
        signer = TimestampSigner(SECRET)
        signed = signer.sign_with_timestamp("hello")
        # Tamper with the signed value
        with pytest.raises(BadSignatureError):
            signer.unsign_with_timestamp(signed + "x")

    def test_wrong_secret_timestamp(self):
        signer1 = TimestampSigner("secret-1")
        signer2 = TimestampSigner("secret-2")
        signed = signer1.sign_with_timestamp("data")
        with pytest.raises(BadSignatureError):
            signer2.unsign_with_timestamp(signed)


class TestConvenienceFunctions:
    def test_make_and_verify_token(self):
        token = make_token("user:42", secret=SECRET)
        assert verify_token(token, secret=SECRET) == "user:42"

    def test_verify_with_max_age(self):
        token = make_token("user:42", secret=SECRET)
        assert verify_token(token, max_age=60, secret=SECRET) == "user:42"

    def test_verify_expired_token(self):
        with patch("tortoise_auth.signing.time.time", return_value=time.time() - 100):
            token = make_token("user:42", secret=SECRET)
        with pytest.raises(SignatureExpiredError):
            verify_token(token, max_age=10, secret=SECRET)

    def test_verify_tampered_token(self):
        token = make_token("user:42", secret=SECRET)
        with pytest.raises(BadSignatureError):
            verify_token(token + "bad", secret=SECRET)

    def test_uses_config_secret(self):
        from tortoise_auth.config import AuthConfig, configure

        configure(AuthConfig(signing_secret="config-secret"))
        try:
            token = make_token("value")
            assert verify_token(token) == "value"
        finally:
            from tortoise_auth import config as cfg_mod

            cfg_mod._config = None
