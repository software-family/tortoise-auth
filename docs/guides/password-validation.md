# Password Validation

tortoise-auth ships with a password validation system that checks candidate
passwords against a configurable chain of validators. When a password fails
one or more checks, **all** failures are collected and reported together so the
caller can present every problem to the user in a single round-trip.

---

## How It Works

The entry point is the `validate_password()` function. It iterates over every
configured validator, calls its `validate()` method, and collects any
`ValueError` exceptions that are raised. If at least one validator rejects the
password, `validate_password()` raises an `InvalidPasswordError` whose `errors`
attribute contains the full list of human-readable failure messages.

```python
from tortoise_auth.validators import validate_password

validate_password("secret123")  # may raise InvalidPasswordError
```

When no explicit validator list is passed, the validators defined in
`AuthConfig.password_validators` are used.

---

## Built-in Validators

tortoise-auth provides four validators out of the box. All four are enabled by
default when you use the standard `AuthConfig`.

### MinimumLengthValidator

Rejects passwords shorter than a configurable threshold.

| Parameter    | Type  | Default |
|--------------|-------|---------|
| `min_length` | `int` | `8`     |

```python
from tortoise_auth.validators.length import MinimumLengthValidator

validator = MinimumLengthValidator(min_length=12)
validator.validate("short")
# ValueError: This password is too short. It must contain at least 12 characters.
```

With the default `min_length=8`, passwords like `"abc"` or `"hello"` are
rejected while `"longer-password"` passes.

---

### CommonPasswordValidator

Rejects passwords that appear in a bundled list of approximately 20,000 commonly
used passwords. The comparison is **case-insensitive** -- `"Password"`,
`"password"`, and `"PASSWORD"` are all treated identically.

| Parameter            | Type                       | Default                         |
|----------------------|----------------------------|---------------------------------|
| `password_list_path` | `str \| Path \| None`      | Bundled `common_passwords.txt`  |

```python
from tortoise_auth.validators.common import CommonPasswordValidator

validator = CommonPasswordValidator()
validator.validate("password")
# ValueError: This password is too common.
```

The password list is lazily loaded on first use and cached as a `frozenset` for
fast lookups. To supply your own list, pass a path to a text file with one
password per line:

```python
validator = CommonPasswordValidator(password_list_path="/path/to/custom_list.txt")
```

---

### NumericPasswordValidator

Rejects passwords that consist entirely of digits. This validator takes no
parameters.

```python
from tortoise_auth.validators.numeric import NumericPasswordValidator

validator = NumericPasswordValidator()
validator.validate("12345678")
# ValueError: This password is entirely numeric.
```

A password like `"123abc"` passes because it is not *entirely* numeric.

---

### UserAttributeSimilarityValidator

Rejects passwords that are too similar to one or more attributes on the user
object. Similarity is measured using `difflib.SequenceMatcher.quick_ratio()`.
For email attributes, both the full email address and the local part (the
portion before `@`) are checked independently.

| Parameter         | Type              | Default      |
|-------------------|-------------------|--------------|
| `user_attributes` | `tuple[str, ...]` | `("email",)` |
| `max_similarity`  | `float`           | `0.7`        |

```python
from tortoise_auth.validators.similarity import UserAttributeSimilarityValidator

validator = UserAttributeSimilarityValidator(
    user_attributes=("email", "username"),
    max_similarity=0.7,
)
validator.validate("johndoe123", user=user)
# ValueError: The password is too similar to the email.
```

If `user` is `None`, this validator is a no-op and the password passes
unconditionally. This allows `validate_password()` to be called during
registration flows where the user object may not exist yet.

---

## Configuring Validators

The default validator chain is defined on `AuthConfig.password_validators`. To
change which validators run, or to adjust their parameters, pass a custom list
when calling `configure()`:

```python
from tortoise_auth import AuthConfig, configure
from tortoise_auth.validators.length import MinimumLengthValidator
from tortoise_auth.validators.common import CommonPasswordValidator
from tortoise_auth.validators.numeric import NumericPasswordValidator
from tortoise_auth.validators.similarity import UserAttributeSimilarityValidator

configure(AuthConfig(
    user_model="models.User",

    password_validators=[
        MinimumLengthValidator(min_length=12),
        CommonPasswordValidator(),
        NumericPasswordValidator(),
        UserAttributeSimilarityValidator(
            user_attributes=("email", "username"),
            max_similarity=0.6,
        ),
    ],
))
```

To disable a validator, omit it from the list. For example, to keep only the
length and numeric checks:

```python
configure(AuthConfig(
    user_model="models.User",

    password_validators=[
        MinimumLengthValidator(min_length=10),
        NumericPasswordValidator(),
    ],
))
```

---

## Error Handling

When validation fails, `validate_password()` raises
`InvalidPasswordError`. Unlike a plain `ValueError`, this exception carries an
`errors` attribute -- a `list[str]` containing one message per failed validator.

```python
from tortoise_auth.exceptions import InvalidPasswordError
from tortoise_auth.validators import validate_password

try:
    validate_password("123")
except InvalidPasswordError as exc:
    for message in exc.errors:
        print(message)
    # This password is too short. It must contain at least 8 characters.
    # This password is too common.
    # This password is entirely numeric.
```

All validators run regardless of earlier failures. This is intentional --
collecting every error at once lets the caller display a complete list of
requirements to the user rather than making them fix problems one at a time.

The exception's string representation (`str(exc)`) joins all messages with a
semicolon for convenience in log output:

```text
This password is too short. It must contain at least 8 characters.; This password is too common.; This password is entirely numeric.
```

---

## Creating a Custom Validator

A validator is any object that satisfies the `PasswordValidator` protocol. The
protocol is defined as a `runtime_checkable` `Protocol` class with two methods:

```python
from typing import Any, Protocol, runtime_checkable

@runtime_checkable
class PasswordValidator(Protocol):
    def validate(self, password: str, user: Any = None) -> None:
        """Raise ValueError with a message on failure."""
        ...

    def get_help_text(self) -> str:
        """Return a human-readable description of the validation rule."""
        ...
```

To create a custom validator, write a class that implements both methods. There
is no base class to inherit from -- structural subtyping (the Protocol) is all
that is required.

### Example: SpecialCharacterValidator

```python
import re
from typing import Any


class SpecialCharacterValidator:
    """Validates that a password contains at least one special character."""

    SPECIAL_PATTERN = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]")

    def __init__(self, min_count: int = 1) -> None:
        self.min_count = min_count

    def validate(self, password: str, user: Any = None) -> None:
        found = len(self.SPECIAL_PATTERN.findall(password))
        if found < self.min_count:
            raise ValueError(
                f"This password must contain at least {self.min_count} "
                f"special character(s)."
            )

    def get_help_text(self) -> str:
        return (
            f"Your password must contain at least {self.min_count} "
            f"special character(s)."
        )
```

Add it to the validator chain alongside the built-in validators:

```python
from tortoise_auth import AuthConfig, configure
from tortoise_auth.validators.length import MinimumLengthValidator
from tortoise_auth.validators.common import CommonPasswordValidator
from tortoise_auth.validators.numeric import NumericPasswordValidator
from tortoise_auth.validators.similarity import UserAttributeSimilarityValidator

configure(AuthConfig(
    user_model="models.User",

    password_validators=[
        MinimumLengthValidator(),
        CommonPasswordValidator(),
        NumericPasswordValidator(),
        UserAttributeSimilarityValidator(),
        SpecialCharacterValidator(min_count=2),
    ],
))
```

!!! tip
    Because `PasswordValidator` is `runtime_checkable`, you can verify at
    startup that your custom class satisfies the protocol:

    ```python
    from tortoise_auth.validators import PasswordValidator

    assert isinstance(SpecialCharacterValidator(), PasswordValidator)
    ```

---

## Passing a User Object

When a user object is available (for example, during a password change), pass it
to `validate_password()` so that attribute-similarity checks can run:

```python
user = await User.get(pk=user_id)
validate_password("new-password", user=user)
```

When `user` is `None`, validators that require user context (such as
`UserAttributeSimilarityValidator`) silently pass. This makes it safe to call
`validate_password()` during registration before the user record exists.

---

## Overriding Validators Per Call

You can bypass the global configuration and supply an explicit validator list
for a single call:

```python
from tortoise_auth.validators import validate_password
from tortoise_auth.validators.length import MinimumLengthValidator

validate_password(
    "candidate-password",
    validators=[MinimumLengthValidator(min_length=16)],
)
```

This is useful in administrative flows or API endpoints that need stricter (or
more lenient) rules than the application default.
