# Configuration Options

Complete reference for every field on the `AuthConfig` dataclass. Pass these
values when calling `configure()` at application startup.

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="change-me",
    argon2_memory_cost=131072,
))
```

All fields have sensible defaults. Only `user_model` is required for a working
setup.

---

## User Model

| Field | Type | Default | Description |
|---|---|---|---|
| `user_model` | `str` | `""` | Dotted path to your concrete user model (e.g. `"myapp.User"`). Must be a subclass of `AbstractUser` and registered with Tortoise ORM. |

!!! warning
    You **must** set `user_model` before calling any authentication method.
    An empty string will cause runtime errors when the library attempts to
    resolve the model.

---

## Password Hashing

These fields control the parameters passed to the underlying password hashing
algorithms. Argon2id is the primary hasher; Bcrypt and PBKDF2-SHA256 are
retained for transparent auto-migration of legacy hashes.

### Argon2

| Field | Type | Default | Description |
|---|---|---|---|
| `argon2_time_cost` | `int` | `3` | Number of iterations (passes over memory). Higher values increase resistance to brute-force attacks at the cost of slower hashing. |
| `argon2_memory_cost` | `int` | `65536` | Memory usage in kibibytes (KiB). The default of 65 536 KiB equals 64 MiB. Increasing this value makes GPU-based attacks significantly more expensive. |
| `argon2_parallelism` | `int` | `4` | Degree of parallelism (number of threads). Should generally match the number of CPU cores available to the hashing process. |

### Bcrypt

| Field | Type | Default | Description |
|---|---|---|---|
| `bcrypt_rounds` | `int` | `12` | Work factor (log2 of the number of rounds). Each increment doubles the computation time. Used only when verifying or migrating legacy Bcrypt hashes. |

### PBKDF2

| Field | Type | Default | Description |
|---|---|---|---|
| `pbkdf2_iterations` | `int` | `600000` | Number of PBKDF2-SHA256 iterations. Used only when verifying or migrating legacy PBKDF2 hashes. The OWASP recommendation as of 2023 is at least 600 000. |

!!! tip
    You rarely need to change hashing parameters unless your threat model or
    hardware profile demands it. The defaults follow current
    [OWASP recommendations](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

---

## Password Validation

| Field | Type | Default | Description |
|---|---|---|---|
| `password_validators` | `list[PasswordValidator]` | See below | List of validator instances that run when a password is created or changed. Each validator must conform to the `PasswordValidator` protocol. |

The default list contains four validators, applied in order:

| # | Validator | Behavior |
|---|---|---|
| 1 | `MinimumLengthValidator()` | Rejects passwords shorter than a configurable minimum (default 8 characters). |
| 2 | `CommonPasswordValidator()` | Rejects passwords that appear in a bundled list of commonly used passwords. |
| 3 | `NumericPasswordValidator()` | Rejects passwords that consist entirely of digits. |
| 4 | `UserAttributeSimilarityValidator()` | Rejects passwords that are too similar to the user's email or other attributes. |

### Password Limits

| Field | Type | Default | Description |
|---|---|---|---|
| `max_password_length` | `int` | `4096` | Maximum allowed password length in characters. Passwords exceeding this limit are rejected by `set_password()` (raises `InvalidPasswordError`) and `check_password()` (returns `False`). Prevents denial-of-service attacks via extremely long passwords that consume hashing resources. |

To replace or extend the defaults, pass your own list:

```python
from tortoise_auth.validators.length import MinimumLengthValidator

configure(AuthConfig(
    user_model="myapp.User",
    password_validators=[
        MinimumLengthValidator(min_length=12),
    ],
))
```

---

## Token Settings

| Field | Type | Default | Description |
|---|---|---|---|
| `access_token_lifetime` | `int` | `900` | Access token lifetime in **seconds**. The default of 900 seconds equals 15 minutes. |
| `refresh_token_lifetime` | `int` | `604800` | Refresh token lifetime in **seconds**. The default of 604 800 seconds equals 7 days. |
| `token_length` | `int` | `64` | Length in bytes of the random opaque token generated for each access and refresh token. The raw bytes are hex-encoded before being returned to the client, so the visible token string will be twice this length. |
| `max_tokens_per_user` | `int` | `100` | Maximum number of active (non-revoked) access tokens per user. When exceeded, the oldest tokens are automatically revoked to stay within the limit. This prevents unbounded token accumulation from repeated logins without logout. |

---

## Signing (HMAC)

These fields configure the HMAC-SHA256 signing utilities (`Signer`,
`TimestampSigner`, `make_token`, and `verify_token`) used for email-confirmation
links, password-reset URLs, and other signed payloads.

| Field | Type | Default | Description |
|---|---|---|---|
| `signing_secret` | `str` | `""` | Secret key used for HMAC-SHA256 signing. This is also used by the `effective_signing_secret` property. |
| `signing_token_lifetime` | `int` | `86400` | Default maximum age in **seconds** for signed tokens. The default of 86 400 seconds equals 24 hours. Individual calls to `verify_token` can override this via the `max_age` keyword argument. |

---

## JWT Settings

These fields configure the JWT token backend (`JWTBackend`). They are only
relevant when using the JWT backend — the database backend ignores them.

| Field | Type | Default | Description |
|---|---|---|---|
| `jwt_secret` | `str` | `""` | Secret key for signing JWTs with HMAC-SHA256. If empty, falls back to `signing_secret`. |
| `jwt_algorithm` | `str` | `"HS256"` | JWT signing algorithm. Only HMAC algorithms (`HS256`, `HS384`, `HS512`) are supported. |
| `jwt_issuer` | `str` | `""` | Value for the `iss` (issuer) claim. When set, tokens include this claim and verification requires a matching issuer. Leave empty to omit. |
| `jwt_audience` | `str` | `""` | Value for the `aud` (audience) claim. When set, tokens include this claim and verification requires a matching audience. Leave empty to omit. |
| `jwt_blacklist_enabled` | `bool` | `False` | Enable the database-backed blacklist for JWT revocation. When `False`, `revoke_token()` and `revoke_all_for_user()` are no-ops. |

!!! tip
    The `access_token_lifetime` and `refresh_token_lifetime` fields from the
    [Token Settings](#token-settings) section are also used by the JWT backend
    to set the `exp` claim on issued tokens.

---

## Onboarding

These fields configure the multi-step onboarding flow engine
(`OnboardingService`). They are only relevant when using the onboarding
feature.

| Field | Type | Default | Description |
|---|---|---|---|
| `onboarding_session_lifetime` | `int` | `3600` | Onboarding session lifetime in **seconds**. The default of 3600 seconds equals 1 hour. |
| `onboarding_session_token_length` | `int` | `64` | Length of the random session token generated for each onboarding flow. Must be at least 32. |
| `onboarding_require_totp` | `bool` | `False` | Whether TOTP setup is required during onboarding. When `True`, `SetupTOTPStep` becomes mandatory and cannot be skipped. |
| `onboarding_max_verification_attempts` | `int` | `5` | Maximum number of incorrect verification code attempts before the session is invalidated. |
| `onboarding_verification_code_ttl` | `int` | `600` | Verification code lifetime in **seconds**. The default of 600 seconds equals 10 minutes. Codes older than this are rejected. |
| `onboarding_invalidate_previous_sessions` | `bool` | `True` | Whether to invalidate existing onboarding sessions for the same email when `start()` is called. Prevents session fixation and concurrent session issues. |

---

## S2S Authentication

These fields configure the server-to-server authentication service
(`S2SService`). They are only relevant when using the S2S feature.

| Field | Type | Default | Description |
|---|---|---|---|
| `s2s_enabled` | `bool` | `False` | Enable S2S authentication. When `False`, `S2SService.authenticate()` raises `ConfigurationError`. Explicit opt-in prevents accidental exposure. |
| `s2s_token_env_var` | `str` | `"S2S_AUTH_TOKEN"` | Name of the environment variable that holds the valid bearer token(s). Supports comma-separated values for token rotation. Must be non-empty when `s2s_enabled` is `True`. |

!!! tip
    The token is read from the environment on every call to `authenticate()`,
    so you can rotate tokens by updating the env var without restarting
    the application.

---

## Validation Rules

Calling `AuthConfig.validate()` can be used to enforce configuration constraints
at startup.

!!! tip
    Call `config.validate()` immediately after constructing your config in your
    startup code. This catches problems before the first request arrives.

---

## Full Example

A production-style configuration that sets every field explicitly:

```python
import os
from tortoise_auth import AuthConfig, configure
from tortoise_auth.validators.length import MinimumLengthValidator
from tortoise_auth.validators.common import CommonPasswordValidator
from tortoise_auth.validators.numeric import NumericPasswordValidator
from tortoise_auth.validators.similarity import UserAttributeSimilarityValidator

configure(AuthConfig(
    # User model
    user_model="myapp.User",

    # Argon2 (primary hasher)
    argon2_time_cost=3,
    argon2_memory_cost=65536,
    argon2_parallelism=4,

    # Bcrypt (legacy migration)
    bcrypt_rounds=12,

    # PBKDF2 (legacy migration)
    pbkdf2_iterations=600_000,

    # Password validation
    password_validators=[
        MinimumLengthValidator(min_length=10),
        CommonPasswordValidator(),
        NumericPasswordValidator(),
        UserAttributeSimilarityValidator(),
    ],

    # Token settings
    access_token_lifetime=900,       # 15 minutes
    refresh_token_lifetime=604_800,  # 7 days
    token_length=64,
    max_tokens_per_user=100,

    # Password limits
    max_password_length=4096,

    # Signing
    signing_secret=os.environ["AUTH_SIGNING_SECRET"],
    signing_token_lifetime=86_400,  # 24 hours

    # JWT (only needed when using JWTBackend)
    jwt_secret=os.environ.get("AUTH_JWT_SECRET", ""),
    jwt_algorithm="HS256",
    jwt_issuer="myapp",
    jwt_audience="myapi",
    jwt_blacklist_enabled=True,

    # Onboarding (only needed when using OnboardingService)
    onboarding_session_lifetime=3600,
    onboarding_session_token_length=64,
    onboarding_require_totp=False,
    onboarding_max_verification_attempts=5,
    onboarding_verification_code_ttl=600,
    onboarding_invalidate_previous_sessions=True,

    # S2S authentication (only needed when using S2SService)
    s2s_enabled=True,
    s2s_token_env_var="S2S_AUTH_TOKEN",
))
```
