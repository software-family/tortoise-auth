# Quick Start

This tutorial walks you through the core workflow of `tortoise-auth` -- from defining a
user model to issuing tokens and logging out. By the end you will have a single, runnable
async script that exercises every fundamental operation.

**Prerequisites** -- make sure you have completed the [Installation](installation.md) steps,
including a database driver (`aiosqlite` for this tutorial).

---

## 1. Define a User model

`tortoise-auth` ships an `AbstractUser` base class that provides the fields every
authentication system needs:

| Field         | Type              | Default            |
|---------------|-------------------|--------------------|
| `email`       | `CharField(255)`  | _(required)_       |
| `password`    | `CharField(255)`  | `""`               |
| `last_login`  | `DatetimeField`   | `None`             |
| `is_active`   | `BooleanField`    | `True`             |
| `is_verified` | `BooleanField`    | `False`            |
| `joined_at`   | `DatetimeField`   | `None`             |
| `created_at`  | `DatetimeField`   | _auto (creation)_  |
| `updated_at`  | `DatetimeField`   | _auto (every save)_|

Because `AbstractUser` is abstract, you **must** create a concrete subclass and add a
primary key field. Create a file called `models.py` in your project:

```python
from tortoise import fields
from tortoise_auth import AbstractUser


class User(AbstractUser):
    id = fields.IntField(primary_key=True)

    class Meta:
        table = "users"
```

!!! tip
    You can add any extra fields you need (e.g. `display_name`, `phone`, `role`) alongside
    the inherited ones. `AbstractUser` only defines the authentication essentials.

---

## 2. Configure Tortoise ORM

Before using any model you need to initialise Tortoise ORM and point it at a database. For
this tutorial we use an **in-memory SQLite** database so there is nothing to install beyond
`aiosqlite`:

```python
from tortoise import Tortoise

await Tortoise.init(
    db_url="sqlite://:memory:",
    modules={"models": ["myapp.models"]},
)
await Tortoise.generate_schemas()
```

!!! note
    Replace `"myapp.models"` with the dotted path to the module that contains your `User`
    class. Tortoise ORM uses this path to discover and register models.

=== "SQLite (development)"

    ```python
    db_url="sqlite://:memory:"
    ```

=== "PostgreSQL"

    ```python
    db_url="postgres://user:pass@localhost:5432/mydb"
    ```

=== "MySQL / MariaDB"

    ```python
    db_url="mysql://user:pass@localhost:3306/mydb"
    ```

---

## 3. Configure tortoise-auth

Call `configure()` once at startup to set the global authentication configuration. At a
minimum you need two values:

- **`user_model`** -- the Tortoise registry path to your concrete user model, in the format
  `"<app_label>.<ModelName>"`. The app label corresponds to the key you used in the
  `modules` dict during `Tortoise.init`.

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    user_model="models.User",
    signing_secret="change-me-in-production",
))
```

!!! warning
    Never hard-code secrets in production code. Load `signing_secret` from an environment
    variable or a secrets manager:

    ```python
    import os

    configure(AuthConfig(
        user_model="models.User",
        signing_secret=os.environ["SIGNING_SECRET"],
    ))
    ```

!!! info "How does `user_model` resolve?"
    The string `"models.User"` tells tortoise-auth to look up
    `Tortoise.apps["models"]["User"]`. This works because the `modules` dict in
    `Tortoise.init` used `"models"` as the app label key.

---

## 4. Create a user

Create the user record first, then call `set_password()` to hash and persist the password
in a single step:

```python
from myapp.models import User

user = await User.create(email="alice@example.com")
await user.set_password("SecurePass123!")
```

`set_password()` does three things:

1. Hashes the raw password using the configured algorithm (Argon2id by default).
2. Saves the hash to the database (`UPDATE ... SET password = ...`).
3. Emits a `password_changed` event for any registered listeners.

!!! tip
    The password is **not** set during `User.create()`. Calling `set_password()` separately
    ensures the raw password is never stored -- only its hash.

---

## 5. Log in

`AuthService` is the high-level entry point for all authentication operations. Instantiate
it and call `login()` with the user's email and password:

```python
from tortoise_auth import AuthService

auth = AuthService()
result = await auth.login("alice@example.com", "SecurePass123!")

print(result.access_token)   # access token (valid for 15 minutes)
print(result.refresh_token)  # refresh token (valid for 7 days)
print(result.user.email)     # alice@example.com
```

`login()` returns an `AuthResult` dataclass with three attributes:

| Attribute        | Type   | Description                              |
|------------------|--------|------------------------------------------|
| `user`           | `User` | The authenticated user model instance.   |
| `access_token`   | `str`  | Short-lived token for accessing resources. |
| `refresh_token`  | `str`  | Long-lived token for obtaining new access tokens. |

Under the hood, `login()`:

1. Looks up the user by email.
2. Verifies the user is active (`is_active=True`).
3. Checks the password against the stored hash.
4. Creates the token pair via the configured token backend.
5. Updates `last_login` to the current timestamp.
6. Emits a `user_login` event.

If any step fails, an `AuthenticationError` is raised with a generic `"Invalid credentials"`
message (to avoid leaking information about which step failed).

---

## 6. Authenticate a request

Once a client has an access token, use `authenticate()` to verify it and retrieve the
corresponding user:

```python
user = await auth.authenticate(result.access_token)
print(user.email)  # alice@example.com
```

This is the method you call on every incoming request that requires authentication. It:

1. Validates the token (looks up by hash, checks expiration and revocation).
2. Looks up the user by the `sub` (subject) claim in the token payload.
3. Confirms the user is still active.

If the token is invalid, expired, or revoked, a `TokenError` subclass is raised:

| Exception           | When it is raised                        |
|---------------------|------------------------------------------|
| `TokenExpiredError` | The token's `exp` claim is in the past.  |
| `TokenInvalidError` | The token cannot be decoded or the type does not match. |
| `TokenRevokedError` | The token has been explicitly revoked.   |

---

## 7. Refresh tokens

Access tokens are intentionally short-lived. When one expires, use the refresh token to
obtain a **new pair** of tokens without asking the user for their password again:

```python
new_tokens = await auth.refresh(result.refresh_token)
print(new_tokens.access_token)   # new access token
print(new_tokens.refresh_token)  # new refresh token
```

`refresh()` returns a `TokenPair` (not an `AuthResult` -- there is no user lookup). It also
**revokes the old refresh token** so it cannot be used again. This is called
**refresh token rotation** and it limits the damage if a refresh token is leaked.

!!! warning
    After calling `refresh()`, the original `result.refresh_token` is no longer valid.
    Always store and use the **new** refresh token returned by this call.

---

## 8. Log out

Revoke the access token so it can no longer be used:

```python
await auth.logout(new_tokens.access_token)
```

After logout, any call to `authenticate()` with the revoked token will raise
`TokenRevokedError`.

!!! info "Revoking all sessions"
    If you need to invalidate every active token for a user (e.g. after a password change),
    use `logout_all()`:

    ```python
    await auth.logout_all(str(user.pk))
    ```

    All tokens for the user are immediately invalidated in the database.

---

## 9. Complete script

Here is everything from the previous sections combined into a single runnable script. Copy
it into a file (e.g. `quickstart.py`), adjust the model import path, and run it:

```python
"""tortoise-auth quick start -- a complete authentication round-trip."""

import asyncio

from tortoise import Tortoise, fields
from tortoise_auth import AbstractUser, AuthConfig, AuthService, configure


# -- 1. Define the User model ------------------------------------------------

class User(AbstractUser):
    id = fields.IntField(primary_key=True)

    class Meta:
        table = "users"


# -- 2 & 3. Initialise Tortoise ORM and tortoise-auth ------------------------

async def main() -> None:
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={
            "models": ["__main__"],
            "tortoise_auth": ["tortoise_auth.models"],
        },
    )
    await Tortoise.generate_schemas()

    configure(AuthConfig(
        user_model="models.User",
        signing_secret="change-me-in-production",
    ))

    auth = AuthService()

    # -- 4. Create a user -----------------------------------------------------
    user = await User.create(email="alice@example.com")
    await user.set_password("SecurePass123!")
    print(f"Created user: {user.email}")

    # -- 5. Log in ------------------------------------------------------------
    result = await auth.login("alice@example.com", "SecurePass123!")
    print(f"Access token:  {result.access_token[:40]}...")
    print(f"Refresh token: {result.refresh_token[:40]}...")

    # -- 6. Authenticate a request --------------------------------------------
    authenticated_user = await auth.authenticate(result.access_token)
    print(f"Authenticated: {authenticated_user.email}")

    # -- 7. Refresh tokens ----------------------------------------------------
    new_tokens = await auth.refresh(result.refresh_token)
    print(f"New access token:  {new_tokens.access_token[:40]}...")
    print(f"New refresh token: {new_tokens.refresh_token[:40]}...")

    # -- 8. Log out -----------------------------------------------------------
    await auth.logout(new_tokens.access_token)
    print("Logged out successfully.")

    await Tortoise.close_connections()


if __name__ == "__main__":
    asyncio.run(main())
```

!!! note
    Because the `User` class is defined in `__main__`, the `modules` dict uses
    `["__main__"]` and the `user_model` is `"models.User"`. In a real project your model
    will live in a dedicated module (e.g. `myapp.models`) and you would use
    `modules={"models": ["myapp.models"]}` instead.

Running the script should produce output similar to:

```text
Created user: alice@example.com
Access token:  a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7...
Refresh token: f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8...
Authenticated: alice@example.com
New access token:  b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1...
New refresh token: c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2...
Logged out successfully.
```

---

## What's next?

Now that you have the basics working, explore these guides to go further:

- **[User Model](../guides/user-model.md)** -- customise fields, add managers, and work
  with `is_verified` and `joined_at`.
- **[Configuration](../guides/configuration.md)** -- tune token lifetimes, hasher
  parameters, and more via `AuthConfig`.
- **[Token Backends](../guides/token-backends.md)** -- understand database-backed tokens
  and how to write custom backends.
- **[Password Hashing](../guides/password-hashing.md)** -- understand the Argon2/bcrypt/PBKDF2
  multi-hasher stack and transparent hash migration.
- **[Password Validation](../guides/password-validation.md)** -- enforce password strength
  rules before `set_password()`.
- **[Events](../guides/events.md)** -- react to `user_login`, `password_changed`, and other
  lifecycle events.
