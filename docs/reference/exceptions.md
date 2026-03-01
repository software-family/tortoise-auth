# Exceptions

All exceptions raised by `tortoise-auth` live in the `tortoise_auth.exceptions` module and
inherit from a single base class, `TortoiseAuthError`. This makes it straightforward to
catch everything the library can throw with one `except` clause while still allowing
fine-grained handling when you need it.

---

## Hierarchy

```text
TortoiseAuthError
├── AuthenticationError
├── InvalidPasswordError
├── InvalidHashError
├── ConfigurationError
├── EventError
├── TokenError
│   ├── TokenExpiredError
│   ├── TokenInvalidError
│   └── TokenRevokedError
└── SigningError
    ├── SignatureExpiredError
    └── BadSignatureError
```

---

## Exception reference

### TortoiseAuthError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `Exception`                    |
| Module   | `tortoise_auth.exceptions`     |

Base class for every exception raised by `tortoise-auth`. Catch this when you want a single
handler for all library errors.

```python
from tortoise_auth.exceptions import TortoiseAuthError

try:
    await auth.login(email, password)
except TortoiseAuthError as exc:
    log.error("tortoise-auth error: %s", exc)
```

---

### AuthenticationError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TortoiseAuthError`            |

Raised when `AuthService.login()` or `AuthService.authenticate()` fails. The error message
is intentionally generic (`"Invalid credentials"`) to avoid leaking information about
whether the email exists or the password was wrong.

---

### InvalidPasswordError

| Detail     | Value                          |
|------------|--------------------------------|
| Parent     | `TortoiseAuthError`            |
| Attribute  | `errors: list[str]`            |

Raised when a password does not satisfy the configured validators. The `errors` attribute
contains one human-readable string per failed validation rule. The default `str()`
representation joins them with `"; "`.

```python
from tortoise_auth.exceptions import InvalidPasswordError

try:
    await user.set_password("short")
except InvalidPasswordError as exc:
    for message in exc.errors:
        print(message)
    # "Password must be at least 8 characters"
    # "Password must contain at least one uppercase letter"
```

---

### InvalidHashError

| Detail     | Value                          |
|------------|--------------------------------|
| Parent     | `TortoiseAuthError`            |
| Attribute  | `hash: str`                    |

Raised when a stored password hash cannot be recognised by any of the configured hashers.
This typically indicates data corruption or a hash produced by an algorithm that is no
longer enabled. The `hash` attribute contains the unrecognised value.

---

### ConfigurationError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TortoiseAuthError`            |

Raised when `configure()` receives an invalid `AuthConfig`. Common causes include a missing
`jwt_secret`, an unresolvable `user_model` path, or mutually exclusive options.

```python
from tortoise_auth import AuthConfig, configure
from tortoise_auth.exceptions import ConfigurationError

try:
    configure(AuthConfig(user_model="models.User", jwt_secret=""))
except ConfigurationError as exc:
    print(exc)  # descriptive message about what is wrong
```

---

### EventError

| Detail     | Value                          |
|------------|--------------------------------|
| Parent     | `TortoiseAuthError`            |
| Attribute  | `event_name: str`              |
| Attribute  | `handler_name: str`            |
| Attribute  | `original: Exception`          |

Raised when a registered event handler raises an unhandled exception. The three attributes
let you identify exactly which handler failed, for which event, and what the underlying
error was.

```python
from tortoise_auth.exceptions import EventError

try:
    await auth.login(email, password)
except EventError as exc:
    log.error(
        "Handler %r for event %r failed: %s",
        exc.handler_name,
        exc.event_name,
        exc.original,
    )
```

---

### TokenError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TortoiseAuthError`            |

Base class for all token-related errors. Catch this when you want a single handler for any
token problem -- expired, invalid, or revoked -- without distinguishing between them.

```python
from tortoise_auth.exceptions import TokenError

try:
    user = await auth.authenticate(access_token)
except TokenError:
    # return 401 regardless of the specific reason
    ...
```

---

### TokenExpiredError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TokenError`                   |

Raised when a JWT token's `exp` claim is in the past. The client should use its refresh
token to obtain a new access token.

---

### TokenInvalidError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TokenError`                   |

Raised when a token is structurally invalid (cannot be decoded) or its `token_type` claim
does not match the expected type. For example, passing a refresh token where an access token
is required triggers this error.

---

### TokenRevokedError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TokenError`                   |

Raised when a token that has been explicitly revoked (via `logout()` or `logout_all()`) is
presented for authentication or refresh.

---

### SigningError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `TortoiseAuthError`            |

Base class for errors related to the low-level HMAC signing utility. Catch this when you
want a single handler for any signing problem.

```python
from tortoise_auth.exceptions import SigningError

try:
    data = signer.unsign(token)
except SigningError:
    # signed token is invalid or expired
    ...
```

---

### SignatureExpiredError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `SigningError`                 |

Raised when a signed token has exceeded its `max_age`. The signature itself is valid, but
the token is no longer accepted because it is too old.

---

### BadSignatureError

| Detail   | Value                          |
|----------|--------------------------------|
| Parent   | `SigningError`                 |

Raised when the HMAC signature on a token does not match the expected value. This means the
token has been tampered with or was signed with a different secret.

---

## Catch patterns

Use the hierarchy to write precise or broad exception handlers depending on your needs.

### Catch everything from the library

```python
from tortoise_auth.exceptions import TortoiseAuthError

try:
    ...
except TortoiseAuthError:
    ...
```

### Catch all token errors

```python
from tortoise_auth.exceptions import TokenError

try:
    user = await auth.authenticate(token)
except TokenError:
    # covers TokenExpiredError, TokenInvalidError, TokenRevokedError
    ...
```

### Catch all signing errors

```python
from tortoise_auth.exceptions import SigningError

try:
    data = signer.unsign(token)
except SigningError:
    # covers SignatureExpiredError, BadSignatureError
    ...
```

### Distinguish between token failure reasons

```python
from tortoise_auth.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
)

try:
    user = await auth.authenticate(token)
except TokenExpiredError:
    # prompt the client to refresh
    ...
except TokenRevokedError:
    # force a full re-login
    ...
except TokenInvalidError:
    # reject the request outright
    ...
```
