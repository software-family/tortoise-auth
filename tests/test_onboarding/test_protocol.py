"""Tests for onboarding protocol compliance."""

from tortoise_auth.onboarding import (
    ClientHint,
    FieldHint,
    OnboardingResult,
    OnboardingStep,
    OnboardingStepStatus,
    StepResult,
)
from tortoise_auth.onboarding.steps import (
    ProfileCompletionStep,
    RegisterStep,
    SetupTOTPStep,
    VerifyEmailStep,
)


class TestOnboardingStepStatus:
    def test_values(self) -> None:
        assert OnboardingStepStatus.PENDING == "pending"
        assert OnboardingStepStatus.IN_PROGRESS == "in_progress"
        assert OnboardingStepStatus.COMPLETED == "completed"
        assert OnboardingStepStatus.SKIPPED == "skipped"


class TestStepResult:
    def test_frozen(self) -> None:
        result = StepResult(success=True)
        assert result.success is True
        assert result.errors == []
        assert result.data == {}

    def test_with_errors(self) -> None:
        result = StepResult(success=False, errors=["bad input"])
        assert result.errors == ["bad input"]


class TestFieldHint:
    def test_defaults(self) -> None:
        hint = FieldHint(name="email", field_type="email")
        assert hint.required is True
        assert hint.label == ""
        assert hint.placeholder == ""
        assert hint.validation == {}


class TestClientHint:
    def test_defaults(self) -> None:
        hint = ClientHint(step_name="register", fields=[])
        assert hint.title == ""
        assert hint.skippable is False
        assert hint.extra == {}


class TestOnboardingResult:
    def test_defaults(self) -> None:
        result = OnboardingResult(
            session_token="tok",
            current_step="register",
            status="in_progress",
            client_hint=None,
            step_result=None,
            auth_result=None,
        )
        assert result.completed_steps == []
        assert result.remaining_steps == []


class TestProtocolCompliance:
    def test_register_step_implements_protocol(self) -> None:
        assert isinstance(RegisterStep(), OnboardingStep)

    def test_verify_email_step_implements_protocol(self) -> None:
        assert isinstance(VerifyEmailStep(), OnboardingStep)

    def test_setup_totp_step_implements_protocol(self) -> None:
        assert isinstance(SetupTOTPStep(), OnboardingStep)

    def test_profile_step_implements_protocol(self) -> None:
        assert isinstance(ProfileCompletionStep(), OnboardingStep)

    def test_register_step_properties(self) -> None:
        step = RegisterStep()
        assert step.name == "register"
        assert step.skippable is False

    def test_verify_email_step_properties(self) -> None:
        step = VerifyEmailStep()
        assert step.name == "verify_email"
        assert step.skippable is False

    def test_setup_totp_step_properties(self) -> None:
        step = SetupTOTPStep()
        assert step.name == "setup_totp"
        assert step.skippable is True

    def test_profile_step_skippable_when_no_required_fields(self) -> None:
        step = ProfileCompletionStep()
        assert step.skippable is True

    def test_profile_step_not_skippable_when_required_fields(self) -> None:
        step = ProfileCompletionStep(required_fields=["phone"])
        assert step.skippable is False
