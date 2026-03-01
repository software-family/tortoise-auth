# Configuration Options

Complete reference for every field on the `AuthConfig` dataclass. Pass these
values when calling `configure()` at application startup.

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    user_model="myapp.User",
    jwt_secret="change-me",
    argon2_memory_cost=131072,
))
```

All fields have sensible defaults. Only `user_model` and `jwt_secret` (when
using the JWT backend) are required for a working setup.

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

To replace or extend the defaults, pass your own list:

```python
from tortoise_auth.validators.length import MinimumLengthValidator

configure(AuthConfig(
    user_model="myapp.User",
    jwt_secret="change-me",
    password_validators=[
        MinimumLengthValidator(min_length=12),
    ],
))
```

---

## JWT

These fields configure the stateless JWT token backend. They are used whenever
`token_backend` is set to `"jwt"` (the default).

| Field | Type | Default | Description |
|---|---|---|---|
| `jwt_secret` | `str` | `""` | Secret key used to sign and verify JWT tokens. **Required** when using the JWT backend. Must be a long, random, unpredictable string. |
| `jwt_algorithm` | `str` | `"HS256"` | Signing algorithm. Supported values include symmetric algorithms (`HS256`, `HS384`, `HS512`) and asymmetric algorithms (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`). |
| `jwt_public_key` | `str` | `""` | PEM-encoded public key for asymmetric algorithms (e.g. `RS256`). **Required** when `jwt_algorithm` starts with `RS` or `ES`. Ignored for symmetric algorithms. |
| `jwt_access_token_lifetime` | `int` | `900` | Access token lifetime in **seconds**. The default of 900 seconds equals 15 minutes. |
| `jwt_refresh_token_lifetime` | `int` | `604800` | Refresh token lifetime in **seconds**. The default of 604 800 seconds equals 7 days. |
| `jwt_issuer` | `str` | `""` | Value written to the `iss` claim and verified on decode. Leave empty to omit the claim entirely. |
| `jwt_audience` | `str` | `""` | Value written to the `aud` claim and verified on decode. Leave empty to skip audience verification. |

!!! warning "Do not hardcode secrets"
    Never commit `jwt_secret` to version control. Load it from an environment
    variable or a secrets manager:

    ```python
    import os

    configure(AuthConfig(
        user_model="myapp.User",
        jwt_secret=os.environ["AUTH_JWT_SECRET"],
    ))
    ```

!!! note "Asymmetric algorithms"
    When using an asymmetric algorithm such as `RS256`, set `jwt_secret` to the
    **private key** (used for signing) and `jwt_public_key` to the
    **public key** (used for verification). The library will raise a
    `ConfigurationError` during validation if `jwt_public_key` is missing.

---

## Token Backend

| Field | Type | Default | Description |
|---|---|---|---|
| `token_backend` | `str` | `"jwt"` | Selects the token backend implementation. Accepted values are `"jwt"` for stateless JSON Web Tokens and `"database"` for server-side opaque tokens stored in the database. |

The two backends differ in their trade-offs:

| Aspect | `"jwt"` | `"database"` |
|---|---|---|
| Storage | Stateless -- no server-side storage required. | Tokens are persisted as hashed rows in `AccessToken` / `RefreshToken` tables. |
| Revocation | Limited -- individual tokens can be blacklisted in memory, but `revoke_all_for_user` is a no-op. | Immediate -- any token can be revoked or bulk-revoked by user. |
| Scalability | Horizontal scaling is trivial since no shared state is needed. | Requires a shared database accessible by all application instances. |

---

## Database Tokens

These fields apply only when `token_backend` is set to `"database"`.

| Field | Type | Default | Description |
|---|---|---|---|
| `db_token_length` | `int` | `64` | Length in bytes of the random opaque token generated for each access and refresh token. The raw bytes are hex-encoded before being returned to the client, so the visible token string will be twice this length. |

!!! note
    Even when using the database backend, `jwt_access_token_lifetime` and
    `jwt_refresh_token_lifetime` are still used to set the expiration timestamps
    on database token records.

---

## Signing (HMAC)

These fields configure the HMAC-SHA256 signing utilities (`Signer`,
`TimestampSigner`, `make_token`, and `verify_token`) used for email-confirmation
links, password-reset URLs, and other signed payloads.

| Field | Type | Default | Description |
|---|---|---|---|
| `signing_secret` | `str` | `""` | Secret key used for HMAC-SHA256 signing. If left empty, the library falls back to `jwt_secret` via the `effective_signing_secret` property. Setting a dedicated signing secret is recommended so that rotating your JWT secret does not invalidate outstanding signed URLs. |
| `signing_token_lifetime` | `int` | `86400` | Default maximum age in **seconds** for signed tokens. The default of 86 400 seconds equals 24 hours. Individual calls to `verify_token` can override this via the `max_age` keyword argument. |

---

## Validation Rules

Calling `AuthConfig.validate()` enforces the following constraints at startup.
`AuthService` calls `validate()` automatically, but you can also call it
explicitly after constructing your config.

| Rule | Error |
|---|---|
| `token_backend == "jwt"` and `jwt_secret` is empty | `ConfigurationError("jwt_secret required for JWT backend")` |
| `jwt_algorithm` starts with `"RS"` and `jwt_public_key` is empty | `ConfigurationError("jwt_public_key required for RS256")` |

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

    # JWT
    jwt_secret=os.environ["AUTH_JWT_SECRET"],
    jwt_algorithm="HS256",
    jwt_access_token_lifetime=900,       # 15 minutes
    jwt_refresh_token_lifetime=604_800,  # 7 days
    jwt_issuer="myapp",
    jwt_audience="myapp-api",

    # Token backend
    token_backend="jwt",

    # Database tokens (ignored when token_backend="jwt")
    db_token_length=64,

    # Signing
    signing_secret=os.environ["AUTH_SIGNING_SECRET"],
    signing_token_lifetime=86_400,  # 24 hours
))
```
