# Token Backends

tortoise-auth ships with two token backends -- **JWT** and **Database** -- and
defines a `TokenBackend` Protocol that lets you plug in your own implementation.
The backend you choose controls how tokens are created, verified, stored, and
revoked.

## Choosing a Backend

| Feature             | JWT (`JWTBackend`)                        | Database (`DatabaseTokenBackend`)               |
|---------------------|-------------------------------------------|-------------------------------------------------|
| **Storage**         | Stateless -- token is self-contained      | Server-side -- tokens stored in two DB tables   |
| **Revocation**      | In-memory `set` of JTIs (per-process)     | Persistent `is_revoked` flag per token row      |
| **Revoke all**      | No-op (cannot enumerate tokens)           | Full support -- marks all user rows as revoked  |
| **Performance**     | No DB round-trip on verify                | One DB query per verify                         |
| **Scalability**     | Scales horizontally without shared state  | Requires shared database                        |
| **Token size**      | Larger (encoded JSON payload)             | Short opaque string (configurable length)       |
| **Setup**           | Needs `jwt_secret` (and `jwt_public_key` for RS256) | Needs `tortoise_auth.models` in Tortoise modules |
| **Best for**        | APIs where instant revocation is not critical | Apps requiring immediate, reliable revocation  |

You select the backend globally through `AuthConfig.token_backend`:

```python
from tortoise_auth import AuthConfig, configure

# Use JWT (default)
configure(AuthConfig(
    jwt_secret="your-secret-key",
    token_backend="jwt",
))

# Use database tokens
configure(AuthConfig(
    jwt_secret="your-secret-key",   # still needed for signing_secret fallback
    token_backend="database",
))
```

You can also inject a specific backend instance into `AuthService` directly:

```python
from tortoise_auth.services.auth import AuthService
from tortoise_auth.tokens.jwt import JWTBackend

auth = AuthService(backend=JWTBackend())
```

---

## JWT Backend

::: info "Module"
    `tortoise_auth.tokens.jwt.JWTBackend`

The JWT backend encodes all token data into a signed JSON Web Token. Tokens are
self-contained and can be verified without a database query.

### Configuration

The following `AuthConfig` fields control JWT behavior:

| Field                       | Type  | Default     | Description                                    |
|-----------------------------|-------|-------------|------------------------------------------------|
| `jwt_secret`                | `str` | `""`        | Signing key (required). For HS256, this is both the signing and verification key. For RS256, this is the **private** key. |
| `jwt_algorithm`             | `str` | `"HS256"`   | JWT algorithm. Supported: `HS256`, `RS256`.    |
| `jwt_public_key`            | `str` | `""`        | Public key for RS256 verification. Required when `jwt_algorithm` starts with `RS`. |
| `jwt_access_token_lifetime` | `int` | `900`       | Access token lifetime in seconds (15 minutes). |
| `jwt_refresh_token_lifetime`| `int` | `604800`    | Refresh token lifetime in seconds (7 days).    |
| `jwt_issuer`                | `str` | `""`        | Optional `iss` claim. When set, verification enforces it. |
| `jwt_audience`              | `str` | `""`        | Optional `aud` claim. When set, verification enforces it. |

### Payload Structure

Each JWT contains the following claims:

```json
{
  "sub": "42",
  "type": "access",
  "jti": "a1b2c3d4e5f6...",
  "iat": 1700000000,
  "exp": 1700000900,
  "iss": "my-app",
  "aud": "my-audience",
  "extra": {"role": "admin"}
}
```

| Claim   | Always present | Description                                          |
|---------|----------------|------------------------------------------------------|
| `sub`   | Yes            | User ID as a string.                                 |
| `type`  | Yes            | `"access"` or `"refresh"`.                           |
| `jti`   | Yes            | Unique token identifier (UUID4 hex).                 |
| `iat`   | Yes            | Issued-at timestamp (Unix epoch).                    |
| `exp`   | Yes            | Expiration timestamp (Unix epoch).                   |
| `iss`   | No             | Issuer. Only included when `jwt_issuer` is set.      |
| `aud`   | No             | Audience. Only included when `jwt_audience` is set.  |
| `extra` | No             | Arbitrary extra claims. Only on **access** tokens, and only when extra kwargs are passed to `create_tokens`. |

### Algorithm Support

**HS256 (default)** -- symmetric HMAC-SHA256. The same `jwt_secret` is used for
both signing and verification.

```python
configure(AuthConfig(
    jwt_secret="your-256-bit-secret",
    jwt_algorithm="HS256",
))
```

**RS256** -- asymmetric RSA-SHA256. Sign with a private key, verify with the
corresponding public key. Useful when token producers and consumers are separate
services.

```python
configure(AuthConfig(
    jwt_secret=private_key_pem,
    jwt_public_key=public_key_pem,
    jwt_algorithm="RS256",
))
```

!!! warning "Validation"
    Calling `config.validate()` raises `ConfigurationError` if `jwt_algorithm`
    starts with `RS` and `jwt_public_key` is empty.

### Revocation Limitations

The JWT backend keeps a `set[str]` of revoked JTI values **in process memory**.
This has two important consequences:

1. **Revocations are lost on restart.** When the process exits, the set is gone.
2. **Revocations are not shared across processes.** In a multi-worker or
   multi-node deployment, revoking a token on one worker does not revoke it on
   another.
3. **`revoke_all_for_user()` is a no-op.** Since JWTs are self-contained, the
   backend has no list of active tokens to iterate over.

If you need reliable, immediate revocation, use the Database backend.

---

## Database Backend

::: info "Module"
    `tortoise_auth.tokens.database.DatabaseTokenBackend`

The Database backend persists every token in the database and verifies tokens by
looking up their hash. This gives you full control over revocation and token
lifecycle.

### Setup

The Database backend requires two Tortoise ORM models: `AccessToken` and
`RefreshToken`. You must register `tortoise_auth.models` in your Tortoise
configuration so the ORM discovers these tables.

```python
TORTOISE_ORM = {
    "connections": {
        "default": "sqlite://db.sqlite3",
    },
    "apps": {
        "models": {
            "models": ["your_app.models", "aerich.models"],
        },
        "tortoise_auth": {
            "models": ["tortoise_auth.models"],
        },
    },
}
```

This creates two tables:

| Table                             | Model          | Purpose                 |
|-----------------------------------|----------------|-------------------------|
| `tortoise_auth_access_tokens`     | `AccessToken`  | Stores access tokens    |
| `tortoise_auth_refresh_tokens`    | `RefreshToken`  | Stores refresh tokens   |

After registering the models, generate and run migrations with your migration
tool (e.g., Aerich) so the tables are created in the database.

### Token Storage

Tokens are **never stored in plaintext**. When a token is created:

1. A cryptographically secure random string is generated (length controlled by
   `AuthConfig.db_token_length`, default `64`).
2. The raw string is hashed with **SHA-256** before being written to the
   database.
3. The raw string is returned to the caller in the `TokenPair`.

On verification, the presented token is hashed again with SHA-256 and looked up
in the database. This means that even if the database is compromised, the raw
tokens cannot be recovered.

### Full Revocation Support

Unlike the JWT backend, the Database backend supports both single-token and
bulk revocation:

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend

backend = DatabaseTokenBackend()

# Revoke a single token (tries access table first, then refresh)
await backend.revoke_token(raw_token)

# Revoke ALL tokens for a user
await backend.revoke_all_for_user("42")
```

`revoke_token` sets `is_revoked = True` on the matching row. It first checks
the access token table; if no row matches, it checks the refresh token table.

`revoke_all_for_user` marks every non-revoked access **and** refresh token for
the given `user_id` as revoked in a single pass.

### Cleaning Up Expired Tokens

Over time, expired tokens accumulate in the database. The `cleanup_expired()`
method deletes all tokens whose `expires_at` is in the past and returns the
total number of deleted rows:

```python
backend = DatabaseTokenBackend()
deleted = await backend.cleanup_expired()
print(f"Removed {deleted} expired tokens")
```

You should call this method periodically -- for example, in a scheduled Celery
or APScheduler task:

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend


async def cleanup_tokens_task() -> None:
    """Periodic task to purge expired tokens from the database."""
    backend = DatabaseTokenBackend()
    deleted = await backend.cleanup_expired()
    logger.info("Cleaned up %d expired tokens", deleted)
```

---

## The `TokenBackend` Protocol

Both built-in backends conform to the `TokenBackend` Protocol defined in
`tortoise_auth.tokens`. You can write your own backend (for example, backed by
Redis) by implementing this Protocol:

```python
from typing import Any, Protocol, runtime_checkable

from tortoise_auth.tokens import TokenPair, TokenPayload


@runtime_checkable
class TokenBackend(Protocol):
    """Protocol that all token backends must satisfy."""

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair: ...
    async def verify_token(self, token: str, *, token_type: str = "access") -> TokenPayload: ...
    async def revoke_token(self, token: str) -> None: ...
    async def revoke_all_for_user(self, user_id: str) -> None: ...
```

Because this is a `runtime_checkable` Protocol, you can verify at runtime that
your class satisfies the interface:

```python
assert isinstance(MyRedisBackend(), TokenBackend)
```

### Writing a Custom Backend

Here is a skeleton for a Redis-backed token backend:

```python
from typing import Any

from tortoise_auth.tokens import TokenBackend, TokenPair, TokenPayload


class RedisTokenBackend:
    """Example: token backend using Redis for storage and revocation."""

    def __init__(self, redis_url: str) -> None:
        self._redis_url = redis_url

    async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair:
        # Generate tokens, store in Redis with TTL matching lifetime
        ...

    async def verify_token(
        self, token: str, *, token_type: str = "access"
    ) -> TokenPayload:
        # Look up token in Redis, check expiration and revocation
        ...

    async def revoke_token(self, token: str) -> None:
        # Delete or mark the token in Redis
        ...

    async def revoke_all_for_user(self, user_id: str) -> None:
        # Delete all tokens for the user from Redis
        ...


# Verify the implementation satisfies the protocol
assert isinstance(RedisTokenBackend("redis://localhost"), TokenBackend)
```

Pass your custom backend to `AuthService`:

```python
from tortoise_auth.services.auth import AuthService

auth = AuthService(backend=RedisTokenBackend("redis://localhost:6379"))
result = await auth.login("user@example.com", "password123")
```

### Methods Reference

| Method               | Parameters                                      | Returns        | Description                                                    |
|----------------------|-------------------------------------------------|----------------|----------------------------------------------------------------|
| `create_tokens`      | `user_id: str`, `**extra: Any`                  | `TokenPair`    | Create an access/refresh token pair for the given user.        |
| `verify_token`       | `token: str`, `token_type: str = "access"`      | `TokenPayload` | Decode and verify a token. Raises on expiration, revocation, or invalidity. |
| `revoke_token`       | `token: str`                                    | `None`         | Revoke a single token so it can no longer be verified.         |
| `revoke_all_for_user`| `user_id: str`                                  | `None`         | Revoke every token belonging to the given user.                |

### Exceptions Raised by Backends

All backends raise exceptions from `tortoise_auth.exceptions`:

| Exception           | When                                           |
|---------------------|-------------------------------------------------|
| `TokenExpiredError` | The token's `exp` claim is in the past.         |
| `TokenInvalidError` | The token cannot be decoded, has the wrong type, or is not found in the database. |
| `TokenRevokedError` | The token has been explicitly revoked.          |

All three inherit from `TokenError`, which inherits from `TortoiseAuthError`.

---

## Data Types

Token backends operate on three frozen dataclasses defined in
`tortoise_auth.tokens`.

### `TokenPair`

Returned by `create_tokens()`. Contains the raw token strings that should be
sent to the client.

```python
@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
```

### `AuthResult`

Returned by `AuthService.login()`. Wraps the authenticated user together with
both tokens.

```python
@dataclass(frozen=True, slots=True)
class AuthResult:
    user: Any
    access_token: str
    refresh_token: str

    @property
    def tokens(self) -> TokenPair:
        """Return just the token pair, without the user object."""
        ...
```

The `.tokens` property is convenient when you need to pass only the token
strings to a serializer or response builder:

```python
result = await auth.login("user@example.com", "password123")

# Access individual fields
print(result.user.email)
print(result.access_token)

# Or extract just the token pair
token_pair: TokenPair = result.tokens
```

### `TokenPayload`

Returned by `verify_token()`. A structured representation of the decoded token,
regardless of which backend produced it.

```python
@dataclass(frozen=True, slots=True)
class TokenPayload:
    sub: str                          # User ID as a string
    token_type: str                   # "access" or "refresh"
    jti: str                          # Unique token identifier
    iat: int                          # Issued-at (Unix epoch)
    exp: int                          # Expiration (Unix epoch)
    extra: dict[str, Any] | None = None  # Extra claims (access tokens only)
```

!!! note
    The Database backend does not populate the `extra` field on
    `TokenPayload`. Extra claims passed to `create_tokens` are currently only
    embedded in JWT access tokens.

---

## Using Backends Directly

While `AuthService` is the recommended entry point for authentication workflows,
you can use backends directly when you need lower-level token operations without
user lookup or event emission.

### Creating and Verifying Tokens

```python
from tortoise_auth.tokens.jwt import JWTBackend
from tortoise_auth.config import AuthConfig, configure

configure(AuthConfig(jwt_secret="my-secret"))

backend = JWTBackend()

# Create tokens
pair = await backend.create_tokens("42", role="admin")
print(pair.access_token)
print(pair.refresh_token)

# Verify the access token
payload = await backend.verify_token(pair.access_token, token_type="access")
print(payload.sub)         # "42"
print(payload.token_type)  # "access"
print(payload.extra)       # {"role": "admin"}

# Verify the refresh token
refresh_payload = await backend.verify_token(
    pair.refresh_token, token_type="refresh"
)
print(refresh_payload.sub)  # "42"
```

### Revoking Tokens

```python
# Revoke a single token
await backend.revoke_token(pair.access_token)

# This now raises TokenRevokedError
await backend.verify_token(pair.access_token)
```

### Database Backend Direct Usage

```python
from tortoise_auth.tokens.database import DatabaseTokenBackend

backend = DatabaseTokenBackend()

# Create tokens (persisted in the database)
pair = await backend.create_tokens("42")

# Verify
payload = await backend.verify_token(pair.access_token)

# Revoke all tokens for a user
await backend.revoke_all_for_user("42")

# Clean up expired tokens
deleted = await backend.cleanup_expired()
```

!!! tip "When to use backends directly"
    Direct backend usage is appropriate for background jobs, management
    commands, or internal services that need to issue or revoke tokens without
    going through the full login flow. For request-handling code that needs
    user authentication, prefer `AuthService`.
