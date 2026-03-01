# Authentication

`AuthService` is the central entry point for all authentication operations in
tortoise-auth. It orchestrates user lookup, password verification, token
issuance, revocation, and lifecycle events behind a small, async-first API.

This guide walks through every method on the service, explains the internal
flow of each operation, and documents the exceptions and events you should
expect.

---

## Creating an AuthService

`AuthService` accepts an optional `AuthConfig` and an optional `TokenBackend`.
Depending on how your application is structured, you can instantiate it in three
different ways.

### Pattern 1 -- Global configuration (recommended)

Call `configure()` once at startup. Every `AuthService()` created afterward will
pick up the global config automatically.

```python
from tortoise_auth import AuthConfig, AuthService, configure

configure(AuthConfig(
    user_model="models.User",
    signing_secret="your-secret-key",
))

# No arguments needed -- uses the global config
auth = AuthService()
```

### Pattern 2 -- Explicit config

Pass an `AuthConfig` directly. This overrides the global config for that
instance and is useful in multi-tenant setups or tests.

```python
from tortoise_auth import AuthConfig, AuthService

config = AuthConfig(
    user_model="models.User",
    access_token_lifetime=600,  # 10 minutes
)
auth = AuthService(config=config)
```

### Pattern 3 -- Explicit backend

Supply your own `TokenBackend` implementation. When a backend is provided,
`AuthService` uses it directly instead of building one from the config.

```python
from tortoise_auth import AuthService
from tortoise_auth.tokens.database import DatabaseTokenBackend

backend = DatabaseTokenBackend()
auth = AuthService(backend=backend)
```

!!! tip "Dependency injection in tests"
    Pattern 3 is the preferred approach for unit tests. Pass a mock or
    in-memory backend to isolate the service from real token storage.

---

## login()

```python
async def login(
    self, identifier: str, password: str, **extra_claims: Any
) -> AuthResult
```

`login()` performs a full credential check and, on success, returns an
`AuthResult` containing the authenticated user object and a fresh token pair.

### Internal flow

The method executes the following steps in order:

1. **Resolve the user model** from the Tortoise ORM registry using the
   `user_model` path in the config.
2. **Look up the user** by email (`email=identifier`). If no user is found, the
   method emits a `user_login_failed` event with `reason="not_found"` and
   raises `AuthenticationError`.
3. **Check `is_active`**. If the user is inactive, the method emits
   `user_login_failed` with `reason="inactive"` and raises
   `AuthenticationError`.
4. **Verify the password** by calling `user.check_password(password)`. If the
   password does not match, the method emits `user_login_failed` with
   `reason="bad_password"` and raises `AuthenticationError`.
5. **Create tokens** via the configured backend, forwarding any
   `extra_claims` as additional payload.
6. **Update `last_login`** on the user record to the current timestamp.
7. **Emit `user_login`** with the user object.
8. **Return an `AuthResult`** containing the user, the access token, and the
   refresh token.

### Usage

```python
from tortoise_auth import AuthService
from tortoise_auth.exceptions import AuthenticationError

auth = AuthService()

try:
    result = await auth.login("alice@example.com", "correct-password")
except AuthenticationError:
    # Handle invalid credentials
    ...

# result.user        -- the authenticated user model instance
# result.access_token  -- short-lived access token string
# result.refresh_token -- long-lived refresh token string
# result.tokens        -- TokenPair(access_token=..., refresh_token=...)
```

### Extra claims

Any additional keyword arguments passed to `login()` are forwarded to the token
backend as extra claims embedded in the access token payload.

```python
result = await auth.login(
    "alice@example.com",
    "correct-password",
    role="admin",
    org_id="acme-corp",
)
```

!!! note
    Extra claims are currently only supported by custom token backends.
    The built-in database backend does not embed extra claims in tokens.

---

## authenticate()

```python
async def authenticate(self, token: str) -> Any
```

`authenticate()` takes a raw access token string, verifies it, and returns the
corresponding user object. This is the method you call on every authenticated
request to resolve the current user.

### Internal flow

1. **Verify the token** via `backend.verify_token(token, token_type="access")`.
   This checks the signature, expiration, revocation status, and token type.
2. **Look up the user** by primary key using the `sub` claim from the token
   payload.
3. **Check `is_active`**. If the user has been deactivated since the token was
   issued, the method raises `AuthenticationError("User is inactive")`.
4. **Return the user** model instance.

### Usage

```python
user = await auth.authenticate(access_token)
```

!!! warning "Token type enforcement"
    `authenticate()` explicitly requests `token_type="access"`. Passing a
    refresh token will raise a `TokenInvalidError` because the token type
    claim will not match.

---

## refresh()

```python
async def refresh(self, refresh_token: str) -> TokenPair
```

`refresh()` exchanges a valid refresh token for a new token pair. The old
refresh token is revoked immediately -- this is called **refresh token
rotation** and prevents replay attacks.

### Internal flow

1. **Verify the refresh token** via
   `backend.verify_token(refresh_token, token_type="refresh")`.
2. **Revoke the old refresh token** via `backend.revoke_token(refresh_token)`.
3. **Create a new token pair** for the same user (`payload.sub`).
4. **Return a `TokenPair`** -- not an `AuthResult`. The user object is not
   loaded during refresh.

### Usage

```python
from tortoise_auth.tokens import TokenPair

new_tokens: TokenPair = await auth.refresh(old_refresh_token)

# new_tokens.access_token
# new_tokens.refresh_token
```

!!! important "Return type"
    `refresh()` returns a `TokenPair`, **not** an `AuthResult`. If you need the
    user object, call `authenticate()` with the new access token.

---

## logout()

```python
async def logout(self, token: str) -> None
```

`logout()` revokes a single access token and emits a `user_logout` event.

### Internal flow

1. **Verify the token** and extract the user identity from the payload.
2. **Look up the user** by primary key.
3. **Revoke the token** via the backend.
4. **Emit `user_logout`** with the user object, if the user was found.

If verification fails (expired token, already revoked, etc.), the method still
attempts to revoke the token but silently swallows the exception. This ensures
that `logout()` is safe to call unconditionally.

### Usage

```python
await auth.logout(access_token)
```

---

## logout_all()

```python
async def logout_all(self, user_id: str) -> None
```

`logout_all()` revokes **every** outstanding token for a given user. This is
useful for "sign out everywhere" functionality or when a user changes their
password.

### Internal flow

1. **Revoke all tokens** for the user via `backend.revoke_all_for_user(user_id)`.
2. **Look up the user** by primary key.
3. **Emit `user_logout`** with the user object, if the user was found.

### Usage

```python
await auth.logout_all(user_id=str(user.pk))
```

All tokens for the user are immediately invalidated in the database.

---

## Error handling

Every method on `AuthService` communicates failures through exceptions.
The table below lists which exceptions each method can raise.

| Method           | Exception               | Condition                                                |
|------------------|-------------------------|----------------------------------------------------------|
| `login()`        | `AuthenticationError`   | User not found, user inactive, or wrong password         |
| `authenticate()` | `AuthenticationError`   | User not found or user inactive                          |
| `authenticate()` | `TokenExpiredError`     | Access token has expired                                 |
| `authenticate()` | `TokenInvalidError`     | Token is malformed or has wrong type                     |
| `authenticate()` | `TokenRevokedError`     | Token has been revoked                                   |
| `refresh()`      | `TokenExpiredError`     | Refresh token has expired                                |
| `refresh()`      | `TokenInvalidError`     | Token is malformed or has wrong type                     |
| `refresh()`      | `TokenRevokedError`     | Refresh token has already been revoked                   |
| `logout()`       | *(none)*                | Errors are caught internally; the method does not raise  |
| `logout_all()`   | *(none)*                | Errors are caught internally; the method does not raise  |
| *(any method)*   | `AuthenticationError`   | `user_model` not configured or not found in the registry |

All token-related exceptions inherit from `TokenError`, which itself inherits
from `TortoiseAuthError`:

```text
TortoiseAuthError
  +-- AuthenticationError
  +-- TokenError
        +-- TokenExpiredError
        +-- TokenInvalidError
        +-- TokenRevokedError
```

### Catching errors in practice

```python
from tortoise_auth.exceptions import (
    AuthenticationError,
    TokenError,
    TokenExpiredError,
)

# Broad catch for any auth failure
try:
    user = await auth.authenticate(token)
except AuthenticationError:
    # User not found or inactive
    ...
except TokenExpiredError:
    # Prompt the client to refresh
    ...
except TokenError:
    # Any other token problem (invalid, revoked, etc.)
    ...
```

---

## Events

`AuthService` emits lifecycle events through the built-in event system. You can
subscribe to these events to implement audit logging, rate limiting, analytics,
or any other cross-cutting concern.

### Event reference

| Event                 | Emitted by        | Arguments                                    |
|-----------------------|-------------------|----------------------------------------------|
| `user_login`          | `login()`         | `user` -- the authenticated user instance    |
| `user_login_failed`   | `login()`         | `identifier` (str), `reason` (str)           |
| `user_logout`         | `logout()`, `logout_all()` | `user` -- the user instance           |

The `user_login_failed` event includes a `reason` keyword argument that
indicates why the login attempt was rejected:

| Reason           | Meaning                                       |
|------------------|-----------------------------------------------|
| `"not_found"`    | No user exists with the given email address   |
| `"inactive"`     | The user account is disabled (`is_active=False`) |
| `"bad_password"` | The email was found but the password was wrong |

!!! note "password_changed event"
    The `password_changed` event is emitted by the user model's password
    management methods, not by `AuthService` directly. See the
    [Events](events.md) guide for full coverage of all available events.

### Subscribing to events

```python
from tortoise_auth.events import on

@on("user_login")
async def on_login(user) -> None:
    """Log successful login attempts."""
    print(f"User {user.email} logged in")

@on("user_login_failed")
async def on_login_failed(*, identifier: str, reason: str) -> None:
    """Track failed login attempts for rate limiting."""
    print(f"Failed login for {identifier}: {reason}")

@on("user_logout")
async def on_logout(user) -> None:
    """Clean up user sessions on logout."""
    print(f"User {user.email} logged out")
```

---

## Security notes

### Generic error messages

`login()` always raises `AuthenticationError("Invalid credentials")`
regardless of the actual failure reason (user not found, account inactive, or
wrong password). This is a deliberate security measure. Returning specific
messages like "user not found" or "wrong password" would allow an attacker to
enumerate valid email addresses.

The specific reason is still available through the `user_login_failed` event
for server-side logging and monitoring, but it is never exposed to the caller.

### Refresh token rotation

`refresh()` revokes the old refresh token **before** issuing a new pair. This
means each refresh token can only be used once. If an attacker intercepts a
refresh token and tries to use it after the legitimate client has already
refreshed, the request will fail with a `TokenRevokedError`.

This pattern is known as **refresh token rotation** and is recommended by
[RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) and the
[OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics).

### Token type enforcement

The `authenticate()` method explicitly validates that the provided token has
`token_type="access"`. A refresh token cannot be used in place of an access
token, and vice versa. This prevents a class of attacks where a longer-lived
refresh token is misused as an access token.

### Active-user checks

Both `login()` and `authenticate()` verify that the user's `is_active` flag is
`True`. This means that deactivating a user account takes effect immediately for
new `authenticate()` calls, even if the user holds a valid, unexpired access
token.

---

Next step: learn about the two available token backends in the
[Token Backends](token-backends.md) guide.
