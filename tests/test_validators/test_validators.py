"""Tests for password validators."""

from types import SimpleNamespace

import pytest

from tortoise_auth.exceptions import InvalidPasswordError
from tortoise_auth.validators import validate_password
from tortoise_auth.validators.common import CommonPasswordValidator
from tortoise_auth.validators.length import MinimumLengthValidator
from tortoise_auth.validators.numeric import NumericPasswordValidator
from tortoise_auth.validators.similarity import UserAttributeSimilarityValidator


class TestMinimumLengthValidator:
    def test_valid_password(self):
        v = MinimumLengthValidator(min_length=8)
        v.validate("abcdefgh")  # no raise

    def test_too_short(self):
        v = MinimumLengthValidator(min_length=8)
        with pytest.raises(ValueError, match="too short"):
            v.validate("abc")

    def test_custom_min_length(self):
        v = MinimumLengthValidator(min_length=4)
        v.validate("abcd")
        with pytest.raises(ValueError):
            v.validate("abc")

    def test_help_text(self):
        v = MinimumLengthValidator(min_length=10)
        assert "10" in v.get_help_text()


class TestCommonPasswordValidator:
    def test_common_password_rejected(self):
        v = CommonPasswordValidator()
        with pytest.raises(ValueError, match="too common"):
            v.validate("password")

    def test_uncommon_password_accepted(self):
        v = CommonPasswordValidator()
        v.validate("j8$kP2!xQm9z")  # unlikely to be common

    def test_case_insensitive(self):
        v = CommonPasswordValidator()
        with pytest.raises(ValueError):
            v.validate("PASSWORD")

    def test_help_text(self):
        v = CommonPasswordValidator()
        assert "commonly used" in v.get_help_text()


class TestNumericPasswordValidator:
    def test_numeric_rejected(self):
        v = NumericPasswordValidator()
        with pytest.raises(ValueError, match="entirely numeric"):
            v.validate("12345678")

    def test_mixed_accepted(self):
        v = NumericPasswordValidator()
        v.validate("1234abcd")

    def test_alpha_accepted(self):
        v = NumericPasswordValidator()
        v.validate("abcdefgh")

    def test_help_text(self):
        v = NumericPasswordValidator()
        assert "numeric" in v.get_help_text()


class TestUserAttributeSimilarityValidator:
    def test_similar_to_email(self):
        v = UserAttributeSimilarityValidator()
        user = SimpleNamespace(email="johndoe@example.com")
        with pytest.raises(ValueError, match="email"):
            v.validate("johndoe@example.com", user)

    def test_similar_to_email_local_part(self):
        v = UserAttributeSimilarityValidator()
        user = SimpleNamespace(email="johndoe@example.com")
        with pytest.raises(ValueError, match="email"):
            v.validate("johndoe", user)

    def test_different_enough(self):
        v = UserAttributeSimilarityValidator()
        user = SimpleNamespace(email="j@x.com")
        v.validate("x7!kP2$qZ", user)  # very different

    def test_no_user(self):
        v = UserAttributeSimilarityValidator()
        v.validate("anything")  # should not raise without user

    def test_custom_max_similarity(self):
        v = UserAttributeSimilarityValidator(max_similarity=0.3)
        user = SimpleNamespace(email="johndoe@example.com")
        with pytest.raises(ValueError):
            v.validate("johnd", user)

    def test_help_text(self):
        v = UserAttributeSimilarityValidator()
        assert "similar" in v.get_help_text()


class TestValidatePassword:
    def test_collects_all_errors(self):
        validators = [
            MinimumLengthValidator(min_length=8),
            NumericPasswordValidator(),
        ]
        with pytest.raises(InvalidPasswordError) as exc_info:
            validate_password("123", validators=validators)

        assert len(exc_info.value.errors) == 2
        assert any("too short" in e for e in exc_info.value.errors)
        assert any("numeric" in e for e in exc_info.value.errors)

    def test_no_errors(self):
        validators = [
            MinimumLengthValidator(min_length=4),
            NumericPasswordValidator(),
        ]
        validate_password("abcdef", validators=validators)

    def test_uses_default_validators_when_none(self):
        # A strong password should pass all defaults
        validate_password("j8$kP2!xQm9zLn")

    def test_single_error(self):
        validators = [MinimumLengthValidator(min_length=20)]
        with pytest.raises(InvalidPasswordError) as exc_info:
            validate_password("short", validators=validators)
        assert len(exc_info.value.errors) == 1
