# API Reference

Complete API reference for `tortoise-auth`, organized by module. Every public class,
function, and data structure is documented with its full signature, parameters, return
type, and exceptions.

For the exception hierarchy and catch patterns, see the dedicated
[Exceptions](exceptions.md) reference.

---

## `tortoise_auth.config`

Configuration management for the library. Call `configure()` once at application startup
to set the global `AuthConfig`. All other modules read from this global instance via
`get_config()`.

### `AuthConfig`

```python
@dataclass
class AuthConfig:
```

Central configuration dataclass. All fields have sensible defaults so you only need to
set the values relevant to your deployment.

#### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `user_model` | `str` | `""` | Tortoise model path in `"app.ModelName"` format. |
| `argon2_time_cost` | `int` | `3` | Argon2 time cost parameter. |
| `argon2_memory_cost` | `int` | `65536` | Argon2 memory cost in KiB. |
| `argon2_parallelism` | `int` | `4` | Argon2 parallelism (threads). |
| `bcrypt_rounds` | `int` | `12` | Bcrypt work factor (log2 rounds). |
| `pbkdf2_iterations` | `int` | `600_000` | PBKDF2-HMAC-SHA256 iteration count. |
| `password_validators` | `list[PasswordValidator]` | See below | List of password validator instances. |
| `access_token_lifetime` | `int` | `900` | Access token lifetime in seconds (15 minutes). |
| `refresh_token_lifetime` | `int` | `604_800` | Refresh token lifetime in seconds (7 days). |
| `token_length` | `int` | `64` | Length of generated opaque tokens for the database backend. |
| `max_tokens_per_user` | `int` | `100` | Maximum active tokens per user before auto-revocation. |
| `max_password_length` | `int` | `4096` | Maximum allowed password length in characters. |
| `signing_secret` | `str` | `""` | HMAC secret for the `signing` module. |
| `signing_token_lifetime` | `int` | `86_400` | Default `max_age` for signed tokens in seconds (24 hours). |
| `jwt_secret` | `str` | `""` | Secret key for signing JWTs. Falls back to `signing_secret` if empty. |
| `jwt_algorithm` | `str` | `"HS256"` | JWT signing algorithm. |
| `jwt_issuer` | `str` | `""` | JWT `iss` claim value. |
| `jwt_audience` | `str` | `""` | JWT `aud` claim value. |
| `jwt_blacklist_enabled` | `bool` | `False` | Enable database-backed JWT blacklist. |
| `onboarding_session_lifetime` | `int` | `3600` | Onboarding session lifetime in seconds (1 hour). |
| `onboarding_session_token_length` | `int` | `64` | Length of the session token. Must be at least 32. |
| `onboarding_require_totp` | `bool` | `False` | Whether TOTP setup is required during onboarding. |
| `onboarding_max_verification_attempts` | `int` | `5` | Max wrong codes before session invalidation. |
| `onboarding_verification_code_ttl` | `int` | `600` | Verification code lifetime in seconds (10 minutes). |
| `onboarding_invalidate_previous_sessions` | `bool` | `True` | Invalidate prior sessions for the same email on `start()`. |

The default `password_validators` list is:

```python
[
    MinimumLengthValidator(),
    CommonPasswordValidator(),
    NumericPasswordValidator(),
    UserAttributeSimilarityValidator(),
]
```

---

#### `AuthConfig.validate`

```python
def validate(self) -> None
```

Validate the configuration and raise on inconsistencies.

---

#### `AuthConfig.effective_signing_secret`

```python
@property
def effective_signing_secret(self) -> str
```

Return `signing_secret`. Used internally by the `signing` module.

**Returns:** The signing secret string.

---

#### `AuthConfig.get_password_hash`

```python
def get_password_hash(self) -> PasswordHash
```

Build a `pwdlib.PasswordHash` instance from the current hasher parameters. Argon2 is
the primary hasher; Bcrypt and PBKDF2 are kept as secondary hashers for transparent
migration of legacy hashes.

**Returns:** A configured `PasswordHash` instance.

---

### `configure`

```python
def configure(config: AuthConfig) -> None
```

Set the global `AuthConfig` instance. Call this once during application startup, before
any authentication operations.

| Parameter | Type | Description |
|---|---|---|
| `config` | `AuthConfig` | The configuration instance to install globally. |

---

### `get_config`

```python
def get_config() -> AuthConfig
```

Retrieve the global `AuthConfig`. If `configure()` has not been called, a default
`AuthConfig()` is created and returned.

**Returns:** The active `AuthConfig` instance.

---

## `tortoise_auth.models`

Tortoise ORM models for users and database-backed tokens.

### `AbstractUser`

```python
class AbstractUser(Model):
    class Meta:
        abstract = True
```

Abstract base model providing authentication fields and password management. Subclass
this in your application and register it with Tortoise ORM.

#### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `email` | `CharField(255)` | `unique=True` | User email address, used as the login identifier. |
| `password` | `CharField(255)` | `default=""` | Hashed password string. |
| `last_login` | `DatetimeField` | `null=True, default=None` | Timestamp of the most recent successful login. |
| `is_active` | `BooleanField` | `default=True` | Whether the user account is active. Inactive users cannot log in. |
| `is_verified` | `BooleanField` | `default=False` | Whether the user has verified their email address. |
| `joined_at` | `DatetimeField` | `null=True, default=None` | Application-defined join timestamp (not auto-set). |
| `created_at` | `DatetimeField` | `auto_now_add=True` | Row creation timestamp (set once, never updated). |
| `updated_at` | `DatetimeField` | `auto_now=True` | Row modification timestamp (updated on every save). |

---

#### `AbstractUser.set_password`

```python
async def set_password(self, raw_password: str) -> None
```

Hash a raw password with the configured primary hasher (Argon2), save the model, and
emit a `"password_changed"` event. Raises `InvalidPasswordError` if the password exceeds
`max_password_length`.

| Parameter | Type | Description |
|---|---|---|
| `raw_password` | `str` | The plaintext password to hash and store. |

**Raises:**

| Exception | Condition |
|---|---|
| `InvalidPasswordError` | The password exceeds `max_password_length` characters. |

---

#### `AbstractUser.check_password`

```python
async def check_password(self, raw_password: str) -> bool
```

Verify a plaintext password against the stored hash. If the hash was produced by a
non-primary hasher (Bcrypt, PBKDF2) or by an older parameter set, the hash is
transparently upgraded and saved.

Returns `False` immediately if the password is unusable or exceeds `max_password_length`.

| Parameter | Type | Description |
|---|---|---|
| `raw_password` | `str` | The plaintext password to verify. |

**Returns:** `True` if the password matches, `False` otherwise.

---

#### `AbstractUser.set_unusable_password`

```python
def set_unusable_password(self) -> None
```

Mark the password as unusable by writing a sentinel value. This is a synchronous
method that mutates the instance in memory. It does **not** save to the database --
call `await self.save()` separately if persistence is required.

---

#### `AbstractUser.has_usable_password`

```python
def has_usable_password(self) -> bool
```

Check whether the stored password is usable (i.e., not a sentinel value set by
`set_unusable_password()`).

**Returns:** `True` if the password can be verified, `False` if it is unusable.

---

#### `AbstractUser.is_authenticated`

```python
@property
def is_authenticated(self) -> bool
```

Always returns `True` for real user instances. Provided for compatibility with
authentication middleware that checks this property.

---

#### `AbstractUser.is_anonymous`

```python
@property
def is_anonymous(self) -> bool
```

Always returns `False` for real user instances.

---

### `AccessToken`

```python
class AccessToken(Model, TokenMixin):
    class Meta:
        table = "tortoise_auth_access_tokens"
```

Database model representing a persisted access token. Used by `DatabaseTokenBackend`.

#### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `id` | `IntField` | `primary_key=True` | Auto-incrementing primary key. |
| `token_hash` | `CharField(64)` | `unique=True, db_index=True` | SHA-256 hex digest of the raw token. |
| `jti` | `CharField(64)` | `unique=True, db_index=True` | Unique token identifier (UUID hex). |
| `user_id` | `CharField(255)` | `db_index=True` | String representation of the owning user's primary key. |
| `created_at` | `DatetimeField` | `auto_now_add=True` | Token creation timestamp. |
| `expires_at` | `DatetimeField` | | Absolute expiration timestamp. |
| `is_revoked` | `BooleanField` | `default=False` | Whether the token has been explicitly revoked. |

---

#### `AccessToken.is_expired`

```python
@property
def is_expired(self) -> bool
```

**Returns:** `True` if `expires_at` is in the past.

---

#### `AccessToken.is_valid`

```python
@property
def is_valid(self) -> bool
```

**Returns:** `True` if the token is neither revoked nor expired.

---

#### `AccessToken.hash_token`

```python
@staticmethod
def hash_token(raw_token: str) -> str
```

Compute the SHA-256 hex digest of a raw token string. Used to look up tokens in the
database without storing them in plaintext.

| Parameter | Type | Description |
|---|---|---|
| `raw_token` | `str` | The raw opaque token. |

**Returns:** A 64-character lowercase hex string.

---

#### `AccessToken.generate_token`

```python
@staticmethod
def generate_token(length: int = 64) -> str
```

Generate a cryptographically secure random token.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `length` | `int` | `64` | Length of the generated token string. |

**Returns:** A URL-safe random string of the specified length.

---

### `RefreshToken`

```python
class RefreshToken(Model, TokenMixin):
    class Meta:
        table = "tortoise_auth_refresh_tokens"
```

Database model representing a persisted refresh token. Identical to `AccessToken` with
the addition of `access_jti`, which links the refresh token to the access token it was
issued alongside.

#### Fields

All fields from `AccessToken`, plus:

| Field | Type | Constraints | Description |
|---|---|---|---|
| `access_jti` | `CharField(64)` | `default=""` | The `jti` of the associated access token. |

#### Properties and static methods

Same as `AccessToken`: `is_expired`, `is_valid`, `hash_token()`, `generate_token()`.

---

### `OutstandingToken`

```python
class OutstandingToken(Model):
    class Meta:
        table = "tortoise_auth_outstanding_tokens"
```

Database model tracking every JWT issued when the blacklist is enabled. Used by
`JWTBackend` to support `revoke_all_for_user()`.

#### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `id` | `IntField` | `primary_key=True` | Auto-incrementing primary key. |
| `jti` | `CharField(64)` | `unique=True, db_index=True` | Unique JWT identifier (UUID hex). |
| `user_id` | `CharField(255)` | `db_index=True` | String representation of the owning user's primary key. |
| `token_type` | `CharField(16)` | | Token type: `"access"` or `"refresh"`. |
| `created_at` | `DatetimeField` | | Token creation timestamp. |
| `expires_at` | `DatetimeField` | | Absolute expiration timestamp. |

---

### `BlacklistedToken`

```python
class BlacklistedToken(Model):
    class Meta:
        table = "tortoise_auth_blacklisted_tokens"
```

Database model storing revoked JWT token identifiers. A token whose JTI appears
in this table will be rejected by `JWTBackend.verify_token()`.

#### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `id` | `IntField` | `primary_key=True` | Auto-incrementing primary key. |
| `jti` | `CharField(64)` | `unique=True, db_index=True` | JTI of the revoked token. |
| `blacklisted_at` | `DatetimeField` | `auto_now_add=True` | Timestamp when the token was blacklisted. |

---

## `tortoise_auth.services`

High-level service layer orchestrating authentication workflows.

### `AuthService`

```python
class AuthService:
    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        backend: TokenBackend | None = None,
    ) -> None
```

High-level authentication service that coordinates login, token verification,
refresh, and logout operations. Resolves the user model from the Tortoise ORM registry
at runtime.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `AuthConfig \| None` | `None` | Configuration override. Falls back to `get_config()`. |
| `backend` | `TokenBackend \| None` | `None` | Token backend override. Uses `DatabaseTokenBackend` when `None`. |

---

#### `AuthService.config`

```python
@property
def config(self) -> AuthConfig
```

**Returns:** The active `AuthConfig`, either the injected instance or the global default.

---

#### `AuthService.backend`

```python
@property
def backend(self) -> TokenBackend
```

**Returns:** The active token backend. If none was injected, instantiates
`DatabaseTokenBackend` from the config.

---

#### `AuthService.login`

```python
async def login(
    self,
    identifier: str,
    password: str,
    **extra_claims: Any,
) -> AuthResult
```

Authenticate a user by email and password. On success, creates a token pair, updates
`last_login`, and emits a `"user_login"` event. On failure, emits a
`"user_login_failed"` event with the failure reason before raising.

| Parameter | Type | Description |
|---|---|---|
| `identifier` | `str` | The user's email address. |
| `password` | `str` | The plaintext password. |
| `**extra_claims` | `Any` | Additional claims forwarded to the token backend. |

**Returns:** An `AuthResult` containing the user instance and the token pair.

**Raises:**

| Exception | Condition |
|---|---|
| `AuthenticationError` | User not found, user is inactive, or password is incorrect. |

---

#### `AuthService.authenticate`

```python
async def authenticate(self, token: str) -> Any
```

Verify an access token and return the corresponding user instance. The user must exist
and be active.

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | A raw access token (opaque database token). |

**Returns:** The user model instance.

**Raises:**

| Exception | Condition |
|---|---|
| `AuthenticationError` | User not found in the database or user is inactive. |
| `TokenExpiredError` | The access token has expired. |
| `TokenInvalidError` | The token is malformed or has an incorrect `token_type`. |
| `TokenRevokedError` | The token has been revoked. |

---

#### `AuthService.refresh`

```python
async def refresh(self, refresh_token: str) -> TokenPair
```

Verify a refresh token, revoke it (one-time use), and issue a new token pair. This
implements refresh token rotation.

| Parameter | Type | Description |
|---|---|---|
| `refresh_token` | `str` | The raw refresh token. |

**Returns:** A new `TokenPair` with fresh access and refresh tokens.

**Raises:**

| Exception | Condition |
|---|---|
| `TokenExpiredError` | The refresh token has expired. |
| `TokenInvalidError` | The token is malformed or has an incorrect `token_type`. |
| `TokenRevokedError` | The refresh token has already been revoked (replay detected). |

---

#### `AuthService.logout`

```python
async def logout(self, token: str) -> None
```

Revoke a single access token. Emits a `"user_logout"` event if the user can be
resolved. If the token is already invalid, the revocation is still attempted without
raising.

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The raw access token to revoke. |

---

#### `AuthService.logout_all`

```python
async def logout_all(self, user_id: str) -> None
```

Revoke all tokens for a given user. Emits a `"user_logout"` event. All active access
and refresh tokens for the user are immediately invalidated in the database.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The string representation of the user's primary key. |

---

## `tortoise_auth.tokens`

Token data structures and the `TokenBackend` protocol.

### `TokenPair`

```python
@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
```

Immutable pair of access and refresh token strings. Returned by
`TokenBackend.create_tokens()` and `AuthService.refresh()`.

| Field | Type | Description |
|---|---|---|
| `access_token` | `str` | The access token (opaque token). |
| `refresh_token` | `str` | The refresh token (opaque token). |

---

### `AuthResult`

```python
@dataclass(frozen=True, slots=True)
class AuthResult:
    user: Any
    access_token: str
    refresh_token: str
```

Result of a successful `AuthService.login()` call. Contains the authenticated user
instance alongside the issued tokens.

| Field | Type | Description |
|---|---|---|
| `user` | `Any` | The authenticated user model instance. |
| `access_token` | `str` | The issued access token. |
| `refresh_token` | `str` | The issued refresh token. |

#### `AuthResult.tokens`

```python
@property
def tokens(self) -> TokenPair
```

**Returns:** A `TokenPair` constructed from `access_token` and `refresh_token`.

---

### `TokenPayload`

```python
@dataclass(frozen=True, slots=True)
class TokenPayload:
    sub: str
    token_type: str
    jti: str
    iat: int
    exp: int
    extra: dict[str, Any] | None = None
```

Decoded token payload returned by `TokenBackend.verify_token()`.

| Field | Type | Description |
|---|---|---|
| `sub` | `str` | Subject -- the user ID as a string. |
| `token_type` | `str` | Token type: `"access"` or `"refresh"`. |
| `jti` | `str` | Unique token identifier (UUID hex). |
| `iat` | `int` | Issued-at timestamp (Unix epoch seconds). |
| `exp` | `int` | Expiration timestamp (Unix epoch seconds). |
| `extra` | `dict[str, Any] \| None` | Additional claims (for custom backends), or `None`. |

---

### `TokenBackend`

```python
@runtime_checkable
class TokenBackend(Protocol):
```

Protocol defining the interface that all token backends must implement. Use this as
the type annotation when accepting a backend dependency.

---

#### `TokenBackend.create_tokens`

```python
async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair
```

Create and return a new access/refresh token pair for the given user.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The user's primary key as a string. |
| `**extra` | `Any` | Additional claims to include in the access token. |

**Returns:** A `TokenPair`.

---

#### `TokenBackend.verify_token`

```python
async def verify_token(
    self,
    token: str,
    *,
    token_type: str = "access",
) -> TokenPayload
```

Decode and verify a token, returning its payload.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token` | `str` | | The raw token string. |
| `token_type` | `str` | `"access"` | Expected token type. Verification fails if the token's type does not match. |

**Returns:** A `TokenPayload`.

**Raises:**

| Exception | Condition |
|---|---|
| `TokenExpiredError` | The token has expired. |
| `TokenInvalidError` | The token is malformed or has the wrong type. |
| `TokenRevokedError` | The token has been revoked. |

---

#### `TokenBackend.revoke_token`

```python
async def revoke_token(self, token: str) -> None
```

Revoke a single token so it can no longer be verified.

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The raw token string to revoke. |

---

#### `TokenBackend.revoke_all_for_user`

```python
async def revoke_all_for_user(self, user_id: str) -> None
```

Revoke every token belonging to a user.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The user's primary key as a string. |

---

## `tortoise_auth.tokens.database`

Database-backed token backend using Tortoise ORM models for full server-side token
lifecycle management.

### `DatabaseTokenBackend`

```python
class DatabaseTokenBackend:
    def __init__(self, config: AuthConfig | None = None) -> None
```

Token backend that persists opaque tokens in the database. Supports immediate and
reliable revocation of individual tokens and bulk revocation of all tokens for a user.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `AuthConfig \| None` | `None` | Configuration override. Falls back to `get_config()`. |

Implements: `TokenBackend`

---

#### `DatabaseTokenBackend.create_tokens`

```python
async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair
```

Generate cryptographically secure opaque tokens, hash them with SHA-256, and persist
the hashes alongside metadata in the `AccessToken` and `RefreshToken` tables. The raw
tokens are returned to the caller and never stored.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The user's primary key as a string. |
| `**extra` | `Any` | Currently unused by the database backend. |

**Returns:** A `TokenPair` containing two opaque token strings.

---

#### `DatabaseTokenBackend.verify_token`

```python
async def verify_token(
    self,
    token: str,
    *,
    token_type: str = "access",
) -> TokenPayload
```

Look up a token by its SHA-256 hash in the appropriate table and verify that it has
not been revoked or expired.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token` | `str` | | The raw opaque token string. |
| `token_type` | `str` | `"access"` | Which table to query: `"access"` or `"refresh"`. |

**Returns:** A `TokenPayload`.

**Raises:**

| Exception | Condition |
|---|---|
| `TokenExpiredError` | The token's `expires_at` is in the past. |
| `TokenInvalidError` | The token hash was not found, or `token_type` is unrecognized. |
| `TokenRevokedError` | The token's `is_revoked` flag is `True`. |

---

#### `DatabaseTokenBackend.revoke_token`

```python
async def revoke_token(self, token: str) -> None
```

Revoke a single token by setting `is_revoked=True`. Tries the access token table
first; if no matching row is found, tries the refresh token table.

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The raw opaque token string. |

---

#### `DatabaseTokenBackend.revoke_all_for_user`

```python
async def revoke_all_for_user(self, user_id: str) -> None
```

Revoke all active access and refresh tokens for a user by setting
`is_revoked=True` on every matching row.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The user's primary key as a string. |

---

#### `DatabaseTokenBackend.cleanup_expired`

```python
async def cleanup_expired(self) -> int
```

Delete all expired tokens from both the access and refresh token tables. Call this
periodically (e.g., from a scheduled task) to keep the database lean.

**Returns:** The total number of deleted rows across both tables.

---

## `tortoise_auth.tokens.jwt`

Stateless JWT token backend using PyJWT, with optional database-backed blacklist
for token revocation.

### `JWTBackend`

```python
class JWTBackend:
    def __init__(self, config: AuthConfig | None = None) -> None
```

Token backend that issues and verifies JSON Web Tokens signed with HMAC-SHA256.
Tokens are stateless by default. When `jwt_blacklist_enabled` is `True`, issued
tokens are tracked in `OutstandingToken` and revoked tokens are recorded in
`BlacklistedToken`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `AuthConfig \| None` | `None` | Configuration override. Falls back to `get_config()`. |

Implements: `TokenBackend`

---

#### `JWTBackend.create_tokens`

```python
async def create_tokens(self, user_id: str, **extra: Any) -> TokenPair
```

Encode two JWTs (access + refresh) with HMAC-SHA256. Claims include `sub`,
`token_type`, `jti`, `iat`, `exp`, and optionally `iss`, `aud`, and `extra`.
When the blacklist is enabled, an `OutstandingToken` record is created for each
token.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The user's primary key as a string. |
| `**extra` | `Any` | Additional claims stored under the `extra` key in the access token. |

**Returns:** A `TokenPair` containing two JWT strings.

---

#### `JWTBackend.verify_token`

```python
async def verify_token(
    self,
    token: str,
    *,
    token_type: str = "access",
) -> TokenPayload
```

Decode and verify a JWT: checks signature, expiration, token type, and (when
blacklist is enabled) that the JTI is not blacklisted.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token` | `str` | | The JWT string. |
| `token_type` | `str` | `"access"` | Expected token type. |

**Returns:** A `TokenPayload`.

**Raises:**

| Exception | Condition |
|---|---|
| `TokenExpiredError` | The token's `exp` claim is in the past. |
| `TokenInvalidError` | Invalid signature, wrong type, missing JTI, or unrecognized token type. |
| `TokenRevokedError` | The token's JTI is in the blacklist (blacklist enabled only). |

---

#### `JWTBackend.revoke_token`

```python
async def revoke_token(self, token: str) -> None
```

Revoke a JWT by adding its JTI to `BlacklistedToken`. When the blacklist is
disabled, this is a no-op. Can revoke already-expired tokens.

| Parameter | Type | Description |
|---|---|---|
| `token` | `str` | The JWT string to revoke. |

---

#### `JWTBackend.revoke_all_for_user`

```python
async def revoke_all_for_user(self, user_id: str) -> None
```

Revoke all tokens for a user by blacklisting their outstanding JTIs. When the
blacklist is disabled, this is a no-op.

| Parameter | Type | Description |
|---|---|---|
| `user_id` | `str` | The user's primary key as a string. |

---

#### `JWTBackend.cleanup_expired`

```python
async def cleanup_expired(self) -> int
```

Delete expired `OutstandingToken` records and their associated `BlacklistedToken`
entries. Call periodically to keep the blacklist tables lean.

**Returns:** The total number of deleted rows across both tables.

---

## `tortoise_auth.hashers`

Password hashing utilities built on [pwdlib](https://frankie567.github.io/pwdlib/).
Argon2id is the primary hasher. Bcrypt and PBKDF2-HMAC-SHA256 are supported as secondary
hashers for transparent migration of legacy hashes.

### `make_password`

```python
def make_password(password: str) -> str
```

Hash a password using the primary hasher (Argon2) with default parameters.

| Parameter | Type | Description |
|---|---|---|
| `password` | `str` | The plaintext password. |

**Returns:** The hashed password string.

---

### `check_password`

```python
def check_password(password: str, hashed: str) -> tuple[bool, str | None]
```

Verify a password against a stored hash. If the hash was produced by a non-primary
hasher or with outdated parameters, `updated_hash` contains the re-hashed value for
transparent migration.

| Parameter | Type | Description |
|---|---|---|
| `password` | `str` | The plaintext password to verify. |
| `hashed` | `str` | The stored hash to verify against. |

**Returns:** A tuple of `(is_valid, updated_hash)`. `updated_hash` is `None` when no
rehash is needed.

---

### `default_password_hash`

```python
def default_password_hash(
    *,
    argon2_time_cost: int = 3,
    argon2_memory_cost: int = 65536,
    argon2_parallelism: int = 4,
    bcrypt_rounds: int = 12,
    pbkdf2_iterations: int = 600_000,
) -> PasswordHash
```

Create a `pwdlib.PasswordHash` instance with all supported hashers. Argon2 is
registered first (primary); Bcrypt and PBKDF2 follow as migration targets.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `argon2_time_cost` | `int` | `3` | Argon2 time cost. |
| `argon2_memory_cost` | `int` | `65536` | Argon2 memory cost in KiB. |
| `argon2_parallelism` | `int` | `4` | Argon2 parallelism (threads). |
| `bcrypt_rounds` | `int` | `12` | Bcrypt work factor. |
| `pbkdf2_iterations` | `int` | `600_000` | PBKDF2 iteration count. |

**Returns:** A configured `PasswordHash` instance.

---

## `tortoise_auth.validators`

Password validation framework. Validators are classes that implement the
`PasswordValidator` protocol. They are run collectively by `validate_password()`, which
collects all errors before raising a single `InvalidPasswordError`.

### `PasswordValidator`

```python
@runtime_checkable
class PasswordValidator(Protocol):
```

Protocol defining the interface for password validators. Implement this protocol to
create custom validators.

---

#### `PasswordValidator.validate`

```python
def validate(self, password: str, user: Any = None) -> None
```

Validate a password. Raise `ValueError` with a human-readable message if the password
does not meet the requirement.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `password` | `str` | | The plaintext password to validate. |
| `user` | `Any` | `None` | Optional user instance for context-aware validation. |

**Raises:**

| Exception | Condition |
|---|---|
| `ValueError` | The password does not meet the validation rule. |

---

#### `PasswordValidator.get_help_text`

```python
def get_help_text(self) -> str
```

**Returns:** A human-readable description of what the validator checks, suitable for
displaying to end users.

---

### `validate_password`

```python
def validate_password(
    password: str,
    user: Model | None = None,
    validators: list[PasswordValidator] | None = None,
) -> None
```

Run all validators against a password and collect errors. If `validators` is `None`,
the defaults from the global `AuthConfig` are used.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `password` | `str` | | The plaintext password to validate. |
| `user` | `Model \| None` | `None` | Optional user instance for context-aware validators. |
| `validators` | `list[PasswordValidator] \| None` | `None` | Custom validator list. Uses `get_config().password_validators` when `None`. |

**Raises:**

| Exception | Condition |
|---|---|
| `InvalidPasswordError` | One or more validators failed. The `errors` attribute contains all failure messages. |

---

### `MinimumLengthValidator`

```python
class MinimumLengthValidator:
    def __init__(self, min_length: int = 8) -> None
```

Rejects passwords shorter than `min_length` characters.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `min_length` | `int` | `8` | Minimum acceptable password length. |

**Help text:** `"Your password must contain at least {min_length} characters."`

---

### `CommonPasswordValidator`

```python
class CommonPasswordValidator:
    def __init__(self, password_list_path: str | Path | None = None) -> None
```

Rejects passwords found in a list of common passwords. The list is loaded lazily on
first use and cached as a `frozenset` for fast lookup.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `password_list_path` | `str \| Path \| None` | `None` | Path to a text file of common passwords (one per line). Defaults to the bundled `common_passwords.txt`. |

**Help text:** `"Your password can't be a commonly used password."`

---

### `NumericPasswordValidator`

```python
class NumericPasswordValidator:
```

Rejects passwords that consist entirely of digits.

Takes no constructor parameters.

**Help text:** `"Your password can't be entirely numeric."`

---

### `UserAttributeSimilarityValidator`

```python
class UserAttributeSimilarityValidator:
    def __init__(
        self,
        user_attributes: tuple[str, ...] = ("email",),
        max_similarity: float = 0.7,
    ) -> None
```

Rejects passwords that are too similar to user attributes (e.g., email address). Uses
`difflib.SequenceMatcher` for similarity comparison. For email attributes, both the
full address and the local part (before `@`) are checked.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `user_attributes` | `tuple[str, ...]` | `("email",)` | Attribute names to compare against on the user instance. |
| `max_similarity` | `float` | `0.7` | Similarity ratio threshold (0.0 to 1.0). Passwords at or above this threshold are rejected. |

**Help text:** `"Your password can't be too similar to your other personal information."`

---

## `tortoise_auth.signing`

HMAC-SHA256 signing utilities for creating URL-safe, tamper-proof tokens. Useful for
email verification links, password reset tokens, and similar one-time-use workflows.

### `Signer`

```python
class Signer:
    def __init__(self, secret: str = "", *, separator: str = ":") -> None
```

HMAC-SHA256 signer that produces URL-safe signed values in the format
`value:signature`. If `secret` is empty, falls back to
`get_config().effective_signing_secret`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `secret` | `str` | `""` | HMAC secret key. Falls back to the global config when empty. |
| `separator` | `str` | `":"` | Character separating the value from the signature. |

---

#### `Signer.sign`

```python
def sign(self, value: str) -> str
```

Sign a value and return the signed string in `value:signature` format.

| Parameter | Type | Description |
|---|---|---|
| `value` | `str` | The plaintext value to sign. |

**Returns:** The signed string.

---

#### `Signer.unsign`

```python
def unsign(self, signed_value: str) -> str
```

Verify the signature and return the original value.

| Parameter | Type | Description |
|---|---|---|
| `signed_value` | `str` | The signed string to verify. |

**Returns:** The original value if the signature is valid.

**Raises:**

| Exception | Condition |
|---|---|
| `BadSignatureError` | The signature does not match or no separator was found. |

---

### `TimestampSigner`

```python
class TimestampSigner(Signer):
    def __init__(self, secret: str = "", *, separator: str = ":") -> None
```

Extends `Signer` with an embedded timestamp, enabling time-limited tokens. The
timestamp is base64-encoded and inserted between the value and the signature.

Inherits all constructor parameters from `Signer`.

---

#### `TimestampSigner.sign_with_timestamp`

```python
def sign_with_timestamp(self, value: str) -> str
```

Sign a value with an embedded Unix timestamp.

| Parameter | Type | Description |
|---|---|---|
| `value` | `str` | The plaintext value to sign. |

**Returns:** The signed string with an embedded timestamp.

---

#### `TimestampSigner.unsign_with_timestamp`

```python
def unsign_with_timestamp(
    self,
    signed_value: str,
    *,
    max_age: int | None = None,
) -> str
```

Verify the signature and optionally check that the token has not exceeded `max_age`
seconds.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `signed_value` | `str` | | The signed string to verify. |
| `max_age` | `int \| None` | `None` | Maximum age in seconds. No expiration check when `None`. |

**Returns:** The original value if the signature is valid and not expired.

**Raises:**

| Exception | Condition |
|---|---|
| `BadSignatureError` | The signature does not match, or the timestamp is malformed. |
| `SignatureExpiredError` | The token age exceeds `max_age`, or the timestamp is in the future. |

---

### `make_token`

```python
def make_token(value: str, secret: str = "") -> str
```

Convenience function to create a timestamped signed token.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `value` | `str` | | The value to sign. |
| `secret` | `str` | `""` | HMAC secret. Falls back to the global config when empty. |

**Returns:** A signed, timestamped token string.

---

### `verify_token`

```python
def verify_token(
    token: str,
    *,
    max_age: int | None = None,
    secret: str = "",
) -> str
```

Convenience function to verify a timestamped signed token and return the original
value.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `token` | `str` | | The signed token to verify. |
| `max_age` | `int \| None` | `None` | Maximum age in seconds. No expiration check when `None`. |
| `secret` | `str` | `""` | HMAC secret. Falls back to the global config when empty. |

**Returns:** The original value.

**Raises:**

| Exception | Condition |
|---|---|
| `BadSignatureError` | The signature is invalid. |
| `SignatureExpiredError` | The token has exceeded `max_age`. |

---

## `tortoise_auth.events`

Async event emitter for lifecycle hooks. The library emits events at key points
(login, logout, password change) so your application can react without coupling to
internal service code.

### Built-in events

| Event name | Arguments | Emitted by |
|---|---|---|
| `"user_login"` | `user` | `AuthService.login()` on success. |
| `"user_login_failed"` | `identifier=, reason=` | `AuthService.login()` on failure. Reason is `"not_found"`, `"inactive"`, or `"bad_password"`. |
| `"user_logout"` | `user` | `AuthService.logout()` and `AuthService.logout_all()`. |
| `"password_changed"` | `user` | `AbstractUser.set_password()`. |
| `"onboarding_started"` | `email=, session_id=, pipeline=` | `OnboardingService.start()`. |
| `"onboarding_step_completed"` | `session_id=, step_name=, user_id=` | `OnboardingService.advance()` on step success. |
| `"onboarding_step_skipped"` | `session_id=, step_name=` | `OnboardingService.advance()` with `skip=True`. |
| `"onboarding_step_failed"` | `session_id=, step_name=, errors=` | `OnboardingService.advance()` on step failure. |
| `"onboarding_completed"` | `user=, session_id=` | `OnboardingService._finalize()` after all steps. |
| `"onboarding_session_expired"` | `session_id=, email=` | When an expired session is accessed. |
| `"verification_code_generated"` | `email=, code=` | `VerifyEmailStep.execute()` phase 1. |

### Handler type

```python
Handler = Callable[..., Coroutine[Any, Any, Any]]
```

All event handlers must be async callables (coroutines).

---

### `EventEmitter`

```python
class EventEmitter:
    def __init__(self, *, propagate_errors: bool = False) -> None
```

Simple async event emitter with sequential handler execution. When `propagate_errors`
is `False` (the default), handler exceptions are logged but do not interrupt the calling
code. When `True`, a failing handler raises `EventError`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `propagate_errors` | `bool` | `False` | Whether to re-raise handler exceptions as `EventError`. |

---

#### `EventEmitter.on`

```python
def on(self, event_name: str) -> Callable[[Handler], Handler]
```

Decorator to register a handler for an event.

| Parameter | Type | Description |
|---|---|---|
| `event_name` | `str` | The event to listen for. |

**Returns:** A decorator that registers the handler and returns it unchanged.

```python
from tortoise_auth.events import on

@on("user_login")
async def handle_login(user):
    ...
```

---

#### `EventEmitter.add_listener`

```python
def add_listener(self, event_name: str, handler: Handler) -> None
```

Register a handler for an event programmatically.

| Parameter | Type | Description |
|---|---|---|
| `event_name` | `str` | The event to listen for. |
| `handler` | `Handler` | The async callable to invoke when the event is emitted. |

---

#### `EventEmitter.remove_listener`

```python
def remove_listener(self, event_name: str, handler: Handler) -> None
```

Remove a previously registered handler. Raises `ValueError` if the handler is not
found in the listener list.

| Parameter | Type | Description |
|---|---|---|
| `event_name` | `str` | The event name. |
| `handler` | `Handler` | The handler to remove. |

---

#### `EventEmitter.emit`

```python
async def emit(self, event_name: str, *args: Any, **kwargs: Any) -> None
```

Emit an event, calling all registered handlers sequentially in registration order. A
snapshot of the listener list is taken before iteration, so handlers added or removed
during emission do not affect the current cycle.

| Parameter | Type | Description |
|---|---|---|
| `event_name` | `str` | The event to emit. |
| `*args` | `Any` | Positional arguments forwarded to each handler. |
| `**kwargs` | `Any` | Keyword arguments forwarded to each handler. |

---

#### `EventEmitter.listeners`

```python
def listeners(self, event_name: str) -> list[Handler]
```

Return a copy of the listener list for an event.

| Parameter | Type | Description |
|---|---|---|
| `event_name` | `str` | The event name. |

**Returns:** A list of registered handlers (copy, safe to mutate).

---

#### `EventEmitter.clear`

```python
def clear(self, event_name: str | None = None) -> None
```

Clear listeners. If `event_name` is `None`, clear all listeners for all events.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `event_name` | `str \| None` | `None` | The event to clear. Clears all events when `None`. |

---

### Module-level convenience aliases

The module provides a pre-instantiated `EventEmitter` and exposes its methods at module
level for convenience:

```python
from tortoise_auth.events import emitter, on, emit, add_listener, remove_listener
```

| Name | Type | Description |
|---|---|---|
| `emitter` | `EventEmitter` | The module-level emitter instance. |
| `on` | method | Alias for `emitter.on`. |
| `emit` | method | Alias for `emitter.emit`. |
| `add_listener` | method | Alias for `emitter.add_listener`. |
| `remove_listener` | method | Alias for `emitter.remove_listener`. |

---

## `tortoise_auth.onboarding`

Protocol, dataclasses, and engine for the server-driven onboarding flow.

### `OnboardingStepStatus`

```python
class OnboardingStepStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
```

Enum tracking the state of each step in the pipeline.

---

### `StepContext`

```python
@dataclass(frozen=True, slots=True)
class StepContext:
    session_id: str
    step_data: dict[str, Any]
    user_id: str | None
    config: AuthConfig
```

Immutable context passed to each step during execution and hint generation.

| Field | Type | Description |
|---|---|---|
| `session_id` | `str` | The onboarding session ID. |
| `step_data` | `dict[str, Any]` | Accumulated data from previous steps. |
| `user_id` | `str \| None` | The user's primary key (string), or `None` until registration completes. |
| `config` | `AuthConfig` | The active configuration. |

---

### `StepResult`

```python
@dataclass(frozen=True, slots=True)
class StepResult:
    success: bool
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    completed: bool = True
```

Result of step execution.

| Field | Type | Default | Description |
|---|---|---|---|
| `success` | `bool` | | Whether the step execution succeeded. |
| `errors` | `list[str]` | `[]` | Human-readable error messages on failure. |
| `data` | `dict[str, Any]` | `{}` | Data to merge into `step_data`. |
| `completed` | `bool` | `True` | Set to `False` for multi-phase steps to stay on the current step. |

---

### `FieldHint`

```python
@dataclass(frozen=True, slots=True)
class FieldHint:
    name: str
    field_type: str
    required: bool = True
    label: str = ""
    placeholder: str = ""
    validation: dict[str, Any] = field(default_factory=dict)
```

Describes a single form field for the client to render.

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | | Field name (used as the key in submitted data). |
| `field_type` | `str` | | Field type hint: `"text"`, `"email"`, `"password"`, `"code"`, `"checkbox"`, etc. |
| `required` | `bool` | `True` | Whether the field is required. |
| `label` | `str` | `""` | Human-readable label. |
| `placeholder` | `str` | `""` | Placeholder text. |
| `validation` | `dict` | `{}` | Validation hints (e.g. `{"length": 6, "pattern": "^\\d{6}$"}`). |

---

### `ClientHint`

```python
@dataclass(frozen=True, slots=True)
class ClientHint:
    step_name: str
    fields: list[FieldHint]
    title: str = ""
    description: str = ""
    skippable: bool = False
    extra: dict[str, Any] = field(default_factory=dict)
```

Describes what the client should render for the current step.

| Field | Type | Default | Description |
|---|---|---|---|
| `step_name` | `str` | | Name of the current step. |
| `fields` | `list[FieldHint]` | | Form fields to display. |
| `title` | `str` | `""` | Step title for the UI. |
| `description` | `str` | `""` | Step description for the UI. |
| `skippable` | `bool` | `False` | Whether the client can offer a "Skip" action. |
| `extra` | `dict` | `{}` | Additional step-specific data (e.g. `action`, `terms_url`, `provisioning_uri`). |

---

### `OnboardingResult`

```python
@dataclass(frozen=True, slots=True)
class OnboardingResult:
    session_token: str
    current_step: str
    status: str
    client_hint: ClientHint | None
    step_result: StepResult | None
    auth_result: AuthResult | None
    completed_steps: list[str] = field(default_factory=list)
    remaining_steps: list[str] = field(default_factory=list)
```

Result returned by `OnboardingService` methods.

| Field | Type | Description |
|---|---|---|
| `session_token` | `str` | The session token for the client. |
| `current_step` | `str` | Name of the current step (empty when completed). |
| `status` | `str` | `"in_progress"`, `"completed"`, or `"error"`. |
| `client_hint` | `ClientHint \| None` | What the client should render. `None` when completed. |
| `step_result` | `StepResult \| None` | Result of the last step execution. `None` on `start()`/`resume()`. |
| `auth_result` | `AuthResult \| None` | Auth tokens, only present when `status="completed"`. |
| `completed_steps` | `list[str]` | Names of completed or skipped steps. |
| `remaining_steps` | `list[str]` | Names of steps not yet completed. |

---

### `OnboardingStep`

```python
@runtime_checkable
class OnboardingStep(Protocol):
```

Protocol defining the interface for onboarding steps. Implement this to create
custom steps.

---

#### `OnboardingStep.name`

```python
@property
def name(self) -> str
```

**Returns:** The unique name of the step (e.g. `"register"`, `"verify_email"`).

---

#### `OnboardingStep.skippable`

```python
@property
def skippable(self) -> bool
```

**Returns:** Whether the step can be skipped by the client.

---

#### `OnboardingStep.is_required`

```python
async def is_required(self, context: StepContext) -> bool
```

Determine whether this step is required for the current flow. Steps that return
`False` are automatically skipped.

---

#### `OnboardingStep.execute`

```python
async def execute(
    self,
    context: StepContext,
    data: dict[str, Any],
) -> StepResult
```

Execute the step with submitted data.

| Parameter | Type | Description |
|---|---|---|
| `context` | `StepContext` | Current flow context. |
| `data` | `dict[str, Any]` | Data submitted by the client. |

**Returns:** A `StepResult`.

---

#### `OnboardingStep.client_hint`

```python
def client_hint(self, context: StepContext) -> ClientHint
```

Generate the `ClientHint` for the current state of this step.

**Returns:** A `ClientHint` describing what the client should render.

---

## `tortoise_auth.onboarding.flow`

### `OnboardingFlow`

```python
class OnboardingFlow:
    def __init__(self, steps: dict[str, OnboardingStep]) -> None
```

Pure state machine engine that drives the pipeline. Contains no I/O of its own;
delegates execution to step instances.

| Parameter | Type | Description |
|---|---|---|
| `steps` | `dict[str, OnboardingStep]` | Map of step name to step instance. |

---

#### `OnboardingFlow.get_next_step`

```python
async def get_next_step(
    self,
    pipeline: list[str],
    current_index: int,
    step_state: dict[str, str],
    context: StepContext,
) -> tuple[int, OnboardingStep] | None
```

Find the next required step starting from `current_index`. Automatically skips
completed, skipped, and non-required steps.

**Returns:** `(index, step)` or `None` if all steps are done.

---

#### `OnboardingFlow.execute_step`

```python
async def execute_step(
    self,
    step: OnboardingStep,
    context: StepContext,
    data: dict[str, Any],
) -> StepResult
```

Delegate execution to a step.

---

#### `OnboardingFlow.handle_skip`

```python
def handle_skip(self, step: OnboardingStep) -> StepResult
```

Attempt to skip a step. Returns `StepResult(success=False)` if the step is not
skippable.

---

#### `OnboardingFlow.is_complete`

```python
def is_complete(
    self,
    pipeline: list[str],
    step_state: dict[str, str],
) -> bool
```

**Returns:** `True` if all pipeline steps are completed or skipped.

---

## `tortoise_auth.onboarding.service`

### `OnboardingService`

```python
class OnboardingService:
    def __init__(
        self,
        config: AuthConfig | None = None,
        *,
        steps: dict[str, OnboardingStep] | None = None,
        pipeline: list[str] | None = None,
        rate_limiter: RateLimitBackend | None = None,
    ) -> None
```

High-level service for managing onboarding flows. Handles session persistence,
step orchestration, event emission, and token issuance on completion.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `AuthConfig \| None` | `None` | Configuration override. Falls back to `get_config()`. |
| `steps` | `dict[str, OnboardingStep] \| None` | `None` | Map of step name to step instance. |
| `pipeline` | `list[str] \| None` | `None` | Ordered list of step names. Defaults to the keys of `steps`. |
| `rate_limiter` | `RateLimitBackend \| None` | `None` | Optional rate limiter for `start()` and `advance()`. |

---

#### `OnboardingService.start`

```python
async def start(
    self,
    email: str,
    *,
    ip_address: str = "",
) -> OnboardingResult
```

Start a new onboarding flow. Creates an `OnboardingSession`, invalidates
previous sessions for the same email (if configured), and returns the first
step's `client_hint`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `email` | `str` | | The email address to onboard. |
| `ip_address` | `str` | `""` | Client IP address (stored for auditing). |

**Returns:** An `OnboardingResult` with `status="in_progress"`.

**Raises:**

| Exception | Condition |
|---|---|
| `RateLimitError` | Rate limiter is configured and the email/IP is throttled. |

**Events emitted:** `onboarding_started`

---

#### `OnboardingService.advance`

```python
async def advance(
    self,
    session_token: str,
    data: dict[str, Any],
    *,
    skip: bool = False,
) -> OnboardingResult
```

Execute (or skip) the current step and advance the flow. When the last step
completes, issues auth tokens via `AuthService`.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `session_token` | `str` | | The raw session token. |
| `data` | `dict[str, Any]` | | Data submitted by the client. |
| `skip` | `bool` | `False` | Skip the current step instead of executing it. |

**Returns:** An `OnboardingResult`. Check `status` for `"in_progress"`,
`"completed"`, or `"error"`.

**Raises:**

| Exception | Condition |
|---|---|
| `OnboardingSessionExpiredError` | The session has expired. |
| `OnboardingSessionInvalidError` | The session is not found or invalidated. |
| `OnboardingFlowCompleteError` | The flow has already been completed. |

**Events emitted:** `onboarding_step_completed`, `onboarding_step_skipped`,
`onboarding_step_failed`, `onboarding_completed`

---

#### `OnboardingService.resume`

```python
async def resume(self, session_token: str) -> OnboardingResult
```

Resume an existing flow without executing anything. Returns the current step's
`client_hint`.

| Parameter | Type | Description |
|---|---|---|
| `session_token` | `str` | The raw session token. |

**Returns:** An `OnboardingResult` with `step_result=None`.

**Raises:**

| Exception | Condition |
|---|---|
| `OnboardingSessionExpiredError` | The session has expired. |
| `OnboardingSessionInvalidError` | The session is not found or invalidated. |
| `OnboardingFlowCompleteError` | The flow has already been completed. |

---

#### `OnboardingService.cleanup_expired`

```python
async def cleanup_expired(self) -> int
```

Delete expired onboarding sessions from the database. Call periodically to keep
the table lean.

**Returns:** The number of deleted sessions.

---

## `tortoise_auth.models.onboarding`

### `OnboardingSession`

```python
class OnboardingSession(Model):
    class Meta:
        table = "tortoise_auth_onboarding_sessions"
```

Database model tracking an in-progress onboarding flow. Stores a SHA-256 hash
of the session token (never the raw value).

#### Fields

| Field | Type | Constraints | Description |
|---|---|---|---|
| `id` | `IntField` | `primary_key=True` | Auto-incrementing primary key. |
| `token_hash` | `CharField(64)` | `unique=True, db_index=True` | SHA-256 hex digest of the raw session token. |
| `email` | `CharField(255)` | `db_index=True` | Email address being onboarded. |
| `user_id` | `CharField(255)` | `db_index=True, default=""` | User primary key (set after registration). |
| `pipeline` | `TextField` | | JSON array of step names. |
| `current_step_index` | `IntField` | `default=0` | Index of the current step in the pipeline. |
| `step_state` | `TextField` | `default="{}"` | JSON object mapping step names to statuses. |
| `step_data` | `TextField` | `default="{}"` | JSON object of accumulated step data. |
| `ip_address` | `CharField(45)` | `default=""` | Client IP address. |
| `created_at` | `DatetimeField` | `auto_now_add=True` | Session creation timestamp. |
| `expires_at` | `DatetimeField` | | Absolute expiration timestamp. |
| `completed_at` | `DatetimeField` | `null=True, default=None` | Flow completion timestamp. |
| `is_invalidated` | `BooleanField` | `default=False` | Whether the session has been invalidated. |

---

#### `OnboardingSession.is_expired`

```python
@property
def is_expired(self) -> bool
```

**Returns:** `True` if `expires_at` is in the past.

---

#### `OnboardingSession.is_valid`

```python
@property
def is_valid(self) -> bool
```

**Returns:** `True` if the session is not invalidated, not expired, and not
completed.

---

#### `hash_session_token`

```python
def hash_session_token(raw: str) -> str
```

Return the SHA-256 hex digest of a raw session token.

---

#### `generate_session_token`

```python
def generate_session_token(length: int) -> str
```

Generate a cryptographically secure random session token.
