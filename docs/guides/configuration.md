# Configuration

tortoise-auth is configured through a single `AuthConfig` dataclass.
You set it once at application startup with `configure()`, and every service
reads it automatically via `get_config()`.  No global settings module,
no magic environment scanning -- you control exactly what goes in.

## The global pattern

```python
from tortoise_auth.config import AuthConfig, configure, get_config

# At startup -- before any service call
configure(AuthConfig(
    user_model="myapp.User",
    signing_secret="change-me-in-production",
))

# Later, anywhere in the application
cfg = get_config()
print(cfg.access_token_lifetime)  # 900
```

`configure()` sets a module-level singleton.  `get_config()` returns it,
creating a default `AuthConfig()` if `configure()` was never called.

!!! warning
    Calling `get_config()` without a prior `configure()` gives you an
    `AuthConfig` with **empty secrets**.  Always call `configure()` explicitly
    during application startup.

---

## Configuration options

Every field on `AuthConfig` has a sensible default.  The table below groups
them by category; each section that follows explains the fields in detail.

### User model

| Field | Type | Default | Description |
|---|---|---|---|
| `user_model` | `str` | `""` | Tortoise model path in `"app_label.ModelName"` format. |

The `user_model` string must match a model registered in the Tortoise ORM
application registry.  `AuthService` resolves it at runtime via
`Tortoise.apps[app_label][model_name]`.

```python
AuthConfig(user_model="myapp.User")
```

If `user_model` is empty or does not contain a dot, `AuthService` raises
`AuthenticationError` with a descriptive message.

### Password hashing

| Field | Type | Default | Description |
|---|---|---|---|
| `argon2_time_cost` | `int` | `3` | Argon2 time cost (iterations). |
| `argon2_memory_cost` | `int` | `65536` | Argon2 memory cost in KiB (64 MB). |
| `argon2_parallelism` | `int` | `4` | Argon2 parallelism (threads). |
| `bcrypt_rounds` | `int` | `12` | bcrypt work factor. |
| `pbkdf2_iterations` | `int` | `600_000` | PBKDF2-SHA256 iteration count. |

These parameters are forwarded to `config.get_password_hash()`, which builds
a `pwdlib.PasswordHash` with Argon2 as the **primary** hasher and bcrypt /
PBKDF2 as legacy migration hashers.  Any password hashed with a non-primary
algorithm is transparently re-hashed to Argon2 on the next successful
verification.

```python
# Increase Argon2 cost for a high-security deployment
AuthConfig(
    argon2_time_cost=4,
    argon2_memory_cost=131072,  # 128 MB
    argon2_parallelism=8,
)
```

!!! tip
    The defaults follow current OWASP recommendations.  Increase memory and
    time costs only if your server hardware can sustain the extra load under
    peak login traffic.

### Password validation

| Field | Type | Default | Description |
|---|---|---|---|
| `password_validators` | `list[PasswordValidator]` | *(see below)* | Ordered list of validators run on every password change. |

The default validator list is:

1. **`MinimumLengthValidator(min_length=8)`** -- rejects passwords shorter than 8 characters.
2. **`CommonPasswordValidator()`** -- rejects passwords found in a bundled common-passwords list.
3. **`NumericPasswordValidator()`** -- rejects passwords that are entirely numeric.
4. **`UserAttributeSimilarityValidator(user_attributes=("email",), max_similarity=0.7)`** -- rejects passwords too similar to user attributes.

All validators implement the `PasswordValidator` protocol and expose two
methods: `validate(password, user=None)` and `get_help_text()`.

Override the list to customize rules:

```python
from tortoise_auth.validators.length import MinimumLengthValidator
from tortoise_auth.validators.common import CommonPasswordValidator

AuthConfig(
    password_validators=[
        MinimumLengthValidator(min_length=12),
        CommonPasswordValidator(),
        # Omit NumericPasswordValidator -- we allow numeric passwords
    ],
)
```

Pass an empty list to disable all validation:

```python
AuthConfig(password_validators=[])
```

### Password limits

| Field | Type | Default | Description |
|---|---|---|---|
| `max_password_length` | `int` | `4096` | Maximum allowed password length in characters. |

Passwords exceeding `max_password_length` are rejected in both
`set_password()` (raises `InvalidPasswordError`) and `check_password()`
(returns `False`). This prevents denial-of-service attacks where an
attacker submits extremely long passwords to consume hashing resources.

```python
AuthConfig(max_password_length=1024)
```

### Token settings

| Field | Type | Default | Description |
|---|---|---|---|
| `access_token_lifetime` | `int` | `900` | Access token lifetime in seconds (15 minutes). |
| `refresh_token_lifetime` | `int` | `604_800` | Refresh token lifetime in seconds (7 days). |
| `token_length` | `int` | `64` | Length of randomly generated opaque tokens. |
| `max_tokens_per_user` | `int` | `100` | Maximum active tokens per user before auto-revocation. |

`DatabaseTokenBackend` uses `access_token_lifetime` and
`refresh_token_lifetime` to set expiration timestamps on database token records.
`token_length` controls the length of the cryptographically random opaque
strings generated for each token.

When a user exceeds `max_tokens_per_user` active tokens, the oldest tokens
are automatically revoked to stay within the limit. This prevents unbounded
token accumulation.

```python
AuthConfig(
    access_token_lifetime=600,      # 10 minutes
    refresh_token_lifetime=86_400,  # 1 day
    token_length=64,
    max_tokens_per_user=50,
)
```

### Signing (HMAC)

| Field | Type | Default | Description |
|---|---|---|---|
| `signing_secret` | `str` | `""` | Dedicated HMAC secret for URL-safe signed tokens. |
| `signing_token_lifetime` | `int` | `86_400` | Default max age for signed tokens in seconds (24 hours). |

The signing module (`tortoise_auth.signing`) uses these values for
email-verification links, password-reset tokens, and similar one-time URLs.

---

## Validation

Call `config.validate()` to eagerly check for configuration problems at
startup rather than discovering them at runtime when a user tries to log in.

```python
from tortoise_auth.config import AuthConfig, configure

config = AuthConfig(
    user_model="myapp.User",
)
config.validate()
configure(config)
```

!!! tip
    Call `config.validate()` immediately after constructing your config in your
    startup code.  This catches typos and missing environment variables before
    the first request arrives.

---

## Derived properties

`AuthConfig` exposes two convenience members that derive their values from
the raw fields.

### `effective_signing_secret`

```python
cfg = AuthConfig(signing_secret="my-key")
assert cfg.effective_signing_secret == "my-key"
```

Returns the `signing_secret` value. The `Signer` and `TimestampSigner` classes
use this property to pick the HMAC key.

### `get_password_hash()`

```python
cfg = AuthConfig(argon2_time_cost=4, argon2_memory_cost=131072)
password_hash = cfg.get_password_hash()
hashed = password_hash.hash("hunter2")
```

Builds and returns a fully configured `pwdlib.PasswordHash` instance.
The returned object supports `hash()`, `verify()`, and
`verify_and_update()`.

---

## Per-service configuration

Every service and backend constructor accepts an optional `config` parameter.
When omitted, the service reads the global config via `get_config()`.  When
provided, the service uses that instance exclusively, ignoring the global
state.

This pattern is useful for testing, multi-tenant setups, or running two
backends side-by-side.

```python
from tortoise_auth.config import AuthConfig
from tortoise_auth.services.auth import AuthService
from tortoise_auth.tokens.database import DatabaseTokenBackend

# Uses global config
default_service = AuthService()

# Uses an explicit config
tenant_config = AuthConfig(
    user_model="tenants.TenantUser",
    signing_secret="tenant-specific-secret",
)
tenant_service = AuthService(config=tenant_config)

# Inject a specific backend directly
db_backend = DatabaseTokenBackend(config=tenant_config)
service_with_db = AuthService(config=tenant_config, backend=db_backend)
```

The classes that accept an optional `config`:

| Class | Module |
|---|---|
| `AuthService` | `tortoise_auth.services.auth` |
| `S2SService` | `tortoise_auth.services.s2s` |
| `DatabaseTokenBackend` | `tortoise_auth.tokens.database` |

Each of these classes resolves the config lazily through a `config` property:

```python
@property
def config(self) -> AuthConfig:
    return self._config or get_config()
```

This means the global config is only consulted if no local config was
injected at construction time.

---

## Example: production configuration

Below is a complete production-ready configuration wired into an async
application startup.  Secrets are loaded from environment variables.

```python
import os

from tortoise import Tortoise

from tortoise_auth.config import AuthConfig, configure

async def init() -> None:
    """Initialize Tortoise ORM and tortoise-auth."""
    await Tortoise.init(
        db_url=os.environ["DATABASE_URL"],
        modules={
            "myapp": ["myapp.models"],
            "tortoise_auth": ["tortoise_auth.models"],
        },
    )
    await Tortoise.generate_schemas()

    config = AuthConfig(
        user_model="myapp.User",

        # Hashing -- tuned for server with 4+ cores and 512 MB+ RAM
        argon2_time_cost=3,
        argon2_memory_cost=65536,
        argon2_parallelism=4,

        # Token lifetimes
        access_token_lifetime=900,       # 15 minutes
        refresh_token_lifetime=604_800,  # 7 days
        token_length=64,
        max_tokens_per_user=100,

        # Password limits
        max_password_length=4096,

        # Signing -- separate secret for email verification tokens
        signing_secret=os.environ["SIGNING_SECRET"],
        signing_token_lifetime=86_400,  # 24 hours
    )
    config.validate()
    configure(config)
```

Key points in this example:

- **Secrets from environment variables** -- `signing_secret` is never hardcoded.
- **`config.validate()` before `configure()`** -- catches missing secrets at
  startup, not on the first login attempt.
- **Database token backend** -- provides immediate revocation via
  `revoke_token()` and `revoke_all_for_user()`.
- **Explicit lifetimes** -- even though the values match the defaults here,
  spelling them out makes the configuration self-documenting.

---

Next step: learn about the token backend in the
[Token Backends](token-backends.md) guide, or see the full field reference in
[Configuration Options](../reference/configuration-options.md).
