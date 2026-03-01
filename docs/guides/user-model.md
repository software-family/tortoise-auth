# User Model

`tortoise-auth` provides `AbstractUser` -- an abstract Tortoise ORM model that gives you
authentication-ready fields and password management out of the box. You subclass it once in your
project, add a primary key, and you are ready to go.

---

## Fields

`AbstractUser` defines the following eight fields. Because the model is abstract, **no database
table is created** until you subclass it.

| Field          | Type                    | Default          | Description                                                                 |
|----------------|-------------------------|------------------|-----------------------------------------------------------------------------|
| `email`        | `CharField(255)`        | -- (required)    | Unique email address. Used as the natural identifier for the user.          |
| `password`     | `CharField(255)`        | `""`             | Stores the hashed password. Never contains the raw password.                |
| `last_login`   | `DatetimeField`         | `None`           | Timestamp of the most recent successful login. Nullable.                    |
| `is_active`    | `BooleanField`          | `True`           | Inactive users are refused authentication regardless of password validity.  |
| `is_verified`  | `BooleanField`          | `False`          | Whether the user has completed email verification.                          |
| `joined_at`    | `DatetimeField`         | `None`           | Application-managed timestamp. Nullable; set it when your onboarding logic completes. |
| `created_at`   | `DatetimeField`         | *auto_now_add*   | Automatically set to the current time when the row is first created.        |
| `updated_at`   | `DatetimeField`         | *auto_now*       | Automatically updated to the current time on every save.                    |

!!! note
    `email` has a `unique=True` constraint at the database level. If you need a
    case-insensitive unique index, add it in your subclass `Meta` or at the database level.

---

## Subclassing AbstractUser

`AbstractUser` is abstract and **does not declare a primary key**. Your subclass must add one.

### With an integer primary key

```python
from tortoise import fields

from tortoise_auth.models import AbstractUser


class User(AbstractUser):
    """Concrete user model with an auto-incrementing integer PK."""

    id = fields.IntField(pk=True)

    class Meta:
        table = "users"
```

### With a UUID primary key

```python
from tortoise import fields

from tortoise_auth.models import AbstractUser


class User(AbstractUser):
    """Concrete user model with a UUID4 primary key."""

    id = fields.UUIDField(pk=True)

    class Meta:
        table = "users"
```

### Adding custom fields

Add any project-specific fields alongside the inherited ones:

```python
from tortoise import fields

from tortoise_auth.models import AbstractUser


class User(AbstractUser):
    """Application user with profile data."""

    id = fields.IntField(pk=True)
    display_name = fields.CharField(max_length=100, default="")
    avatar_url = fields.CharField(max_length=500, default="")
    role = fields.CharField(max_length=50, default="member")

    class Meta:
        table = "users"
```

!!! warning
    Do **not** override the `email` or `password` fields unless you fully understand the
    implications. The authentication pipeline depends on their exact semantics.

---

## Password Methods

`AbstractUser` provides four methods for password management. The hashing backend is Argon2id
by default (via `pwdlib`), with bcrypt and PBKDF2 supported as secondary hashers for
migration purposes.

### `set_password(raw_password)`

```python
await user.set_password("n3w-s3cure-p@ss!")
```

| Aspect      | Detail                                                                                       |
|-------------|----------------------------------------------------------------------------------------------|
| Signature   | `async def set_password(self, raw_password: str) -> None`                                    |
| Hashing     | Uses the primary hasher (Argon2id) from the current `AuthConfig`.                            |
| Persistence | Saves the new hash to the database immediately (`update_fields=["password"]`).               |
| Event       | Emits the `password_changed` event with the user instance after the save completes.          |

### `check_password(raw_password)`

```python
is_valid: bool = await user.check_password("candidate-password")
```

| Aspect          | Detail                                                                                    |
|-----------------|-------------------------------------------------------------------------------------------|
| Signature       | `async def check_password(self, raw_password: str) -> bool`                               |
| Unusable        | Returns `False` immediately if the stored password is [unusable](#unusable-passwords).     |
| Verification    | Delegates to `pwdlib.PasswordHash.verify_and_update`, which tries all registered hashers. |
| Hash migration  | If the hash was produced by a non-primary hasher, re-hashes to Argon2id and saves. See [Hash Migration](#hash-migration). |
| Error handling  | Catches all hashing exceptions and returns `False`.                                       |

### `set_unusable_password()`

```python
user.set_unusable_password()
await user.save(update_fields=["password"])
```

| Aspect      | Detail                                                                                       |
|-------------|----------------------------------------------------------------------------------------------|
| Signature   | `def set_unusable_password(self) -> None`                                                    |
| Behavior    | Replaces the password field with a token prefixed by `!` followed by 40 random characters.   |
| Persistence | Does **not** save to the database. Call `await user.save()` explicitly afterwards.           |
| Use case    | Social-auth users or accounts that must not allow password-based login.                      |

### `has_usable_password()`

```python
if user.has_usable_password():
    # allow password-based login flow
    ...
```

| Aspect    | Detail                                                         |
|-----------|-----------------------------------------------------------------|
| Signature | `def has_usable_password(self) -> bool`                        |
| Returns   | `False` if the password is empty or starts with `!`.           |
| Sync      | This is a synchronous method -- no `await` needed.             |

---

## Hash Migration

`tortoise-auth` ships with three hashers registered in priority order:

1. **Argon2id** -- primary hasher (used for all new hashes)
2. **bcrypt** -- secondary, kept for migration
3. **PBKDF2** -- secondary, kept for migration

When `check_password` verifies a password that was hashed with a non-primary hasher (e.g.,
bcrypt or PBKDF2), `pwdlib` returns an updated hash using the primary hasher. `AbstractUser`
then saves this updated hash to the database transparently. On the next login the user's
password will already be stored as Argon2id.

```text
User logs in
  |
  v
check_password("my-password")
  |
  v
pwdlib.verify_and_update(raw, stored_bcrypt_hash)
  |
  +--> valid=True, updated_hash="$argon2id$..."
  |
  v
Save updated_hash to DB  <-- transparent migration
  |
  v
Return True
```

!!! tip
    This makes it safe to migrate from a Django project using bcrypt or PBKDF2. Import your
    existing password hashes as-is -- they will be upgraded to Argon2id on each user's
    next successful login.

---

## Properties

`AbstractUser` exposes two read-only properties for compatibility with common authentication
patterns:

| Property           | Return type | Value              | Purpose                                                         |
|--------------------|-------------|--------------------|-----------------------------------------------------------------|
| `is_authenticated` | `bool`      | Always `True`      | Distinguishes real user instances from anonymous placeholders.  |
| `is_anonymous`     | `bool`      | Always `False`     | The inverse of `is_authenticated`.                              |

```python
if user.is_authenticated:
    # This is always True for instances of AbstractUser subclasses.
    grant_access(user)
```

!!! note
    These properties exist on the model instance itself. If you need an anonymous user
    concept, create a separate lightweight class with `is_authenticated = False` and
    `is_anonymous = True` rather than modifying these properties.

---

## Unusable Passwords

An unusable password is a random string prefixed with `!`. It is generated by
`make_unusable_password()` and is designed to never match any raw password input.

| Function                   | Description                                                  |
|----------------------------|--------------------------------------------------------------|
| `set_unusable_password()`  | Sets the password field to an unusable value (does not save). |
| `has_usable_password()`    | Returns `False` if the password is empty or starts with `!`. |
| `check_password()`         | Returns `False` immediately for unusable passwords.          |

This is useful for users who authenticate exclusively through OAuth, SAML, or other
external identity providers and should never be able to log in with a password.

---

## Full Example

A complete setup combining subclassing, password management, and the event system:

```python
from tortoise import fields

from tortoise_auth.events import on
from tortoise_auth.models import AbstractUser


class User(AbstractUser):
    """Application user."""

    id = fields.IntField(pk=True)
    display_name = fields.CharField(max_length=150, default="")

    class Meta:
        table = "users"

    def __str__(self) -> str:
        return self.email


@on("password_changed")
async def notify_password_change(user: User) -> None:
    """Send a notification when a user changes their password."""
    # your notification logic here
    ...


async def create_user(email: str, raw_password: str) -> User:
    """Create a new user with a hashed password."""
    user = await User.create(email=email)
    await user.set_password(raw_password)
    return user


async def authenticate(email: str, raw_password: str) -> User | None:
    """Return the user if credentials are valid, otherwise None."""
    user = await User.get_or_none(email=email)
    if user is None:
        return None
    if not user.is_active:
        return None
    if not await user.check_password(raw_password):
        return None
    return user
```

---

Next step: see the [Configuration](configuration.md) guide to tune Argon2 parameters,
token settings, and password validators.
