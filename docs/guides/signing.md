# Signing

HMAC signing lets you create tamper-proof tokens that can be verified later without
a database lookup. tortoise-auth ships a signing module built on **HMAC-SHA256** with
URL-safe base64 encoding, suitable for email-confirmation links, password-reset URLs,
invite tokens, and any other scenario where you need a short-lived, stateless proof
of authenticity.

---

## How HMAC signing works

HMAC (Hash-based Message Authentication Code) combines a secret key with the message
to produce a fixed-length digest. Only someone who possesses the same secret can
reproduce the digest, which means:

1. The **recipient** can verify that the token was created by your application.
2. Any modification to the payload -- even a single character -- invalidates the
   signature.

tortoise-auth uses **HMAC-SHA256** and encodes the resulting digest as URL-safe
base64 (padding stripped). The signed output is a plain string safe for use in
URLs, query parameters, and email links.

---

## Quick start -- convenience functions

For the most common use case -- creating a signed token and verifying it later --
use the module-level `make_token` and `verify_token` helpers. Both functions wrap
`TimestampSigner` internally, so every token carries an embedded timestamp.

### Creating a token

```python
from tortoise_auth.signing import make_token

token = make_token("user-42")
# Example output: "user-42:MTcwOTI5MDAwMA:hK7z..."
```

The returned string contains the original value, a base64-encoded Unix timestamp,
and the HMAC-SHA256 signature, all joined by the default separator (`:`).

### Verifying a token

```python
from tortoise_auth.signing import verify_token
from tortoise_auth.exceptions import BadSignatureError, SignatureExpiredError

try:
    original = verify_token(token, max_age=3600)  # expire after 1 hour
    print(original)  # "user-42"
except SignatureExpiredError:
    print("Token has expired")
except BadSignatureError:
    print("Token is invalid")
```

When `max_age` is provided (in seconds), `verify_token` checks the embedded
timestamp and raises `SignatureExpiredError` if the token is older than the
specified duration. Pass `max_age=None` (the default) to skip the expiration
check entirely.

---

## Signer

`Signer` is the low-level building block. It signs a string value and appends the
HMAC-SHA256 signature, separated by a configurable separator character.

### Constructor

```python
from tortoise_auth.signing import Signer

signer = Signer(secret="my-secret", separator=":")
```

| Parameter   | Type  | Default | Description                                    |
|-------------|-------|---------|------------------------------------------------|
| `secret`    | `str` | `""`    | HMAC key. Falls back to `effective_signing_secret` when empty. |
| `separator` | `str` | `":"`   | Character placed between the value and the signature.           |

### sign

```python
signed = signer.sign("hello")
# "hello:<url-safe-base64-signature>"
```

Returns a string in the format `value<separator>signature`.

### unsign

```python
original = signer.unsign(signed)
# "hello"
```

Verifies the signature using constant-time comparison (`hmac.compare_digest`) and
returns the original value. Raises `BadSignatureError` if the signature is missing
or does not match.

### Full example

```python
from tortoise_auth.signing import Signer
from tortoise_auth.exceptions import BadSignatureError

signer = Signer()

signed = signer.sign("account-deletion-request:99")
print(signed)
# "account-deletion-request:99:<signature>"

# Successful unsign
value = signer.unsign(signed)
assert value == "account-deletion-request:99"

# Tampered payload
try:
    signer.unsign(signed.replace("99", "1"))
except BadSignatureError:
    print("Signature mismatch detected")
```

---

## TimestampSigner

`TimestampSigner` extends `Signer` by embedding a base64-encoded Unix timestamp
into the signed payload. This allows you to enforce a maximum token age at
verification time.

### sign_with_timestamp

```python
from tortoise_auth.signing import TimestampSigner

ts_signer = TimestampSigner()
signed = ts_signer.sign_with_timestamp("user@example.com")
# "user@example.com:<base64-timestamp>:<signature>"
```

The timestamp records the moment of signing as a Unix epoch integer.

### unsign_with_timestamp

```python
original = ts_signer.unsign_with_timestamp(signed, max_age=86400)
# "user@example.com"
```

| Parameter   | Type           | Default | Description                                          |
|-------------|----------------|---------|------------------------------------------------------|
| `max_age`   | `int \| None`  | `None`  | Maximum allowed age in seconds. `None` disables the check. |

Behavior:

- Verifies the HMAC signature first. Raises `BadSignatureError` on mismatch.
- If `max_age` is set, computes the token's age from the embedded timestamp.
  Raises `SignatureExpiredError` when the age exceeds `max_age` or when the
  timestamp is in the future.
- Returns the original value (without the timestamp or signature).

### Full example

```python
import time
from tortoise_auth.signing import TimestampSigner
from tortoise_auth.exceptions import BadSignatureError, SignatureExpiredError

signer = TimestampSigner(secret="my-app-secret")

# Sign
token = signer.sign_with_timestamp("reset-password:42")

# Verify within the allowed window
try:
    value = signer.unsign_with_timestamp(token, max_age=600)  # 10 minutes
    print(f"Valid: {value}")
except SignatureExpiredError as exc:
    print(f"Expired: {exc}")
except BadSignatureError as exc:
    print(f"Invalid: {exc}")
```

---

## Configuration

The signing module reads its secret from `AuthConfig`. You can provide an explicit
secret to any signer or helper function, but when omitted, the library resolves the
secret automatically.

### effective_signing_secret

Set `signing_secret` in your `AuthConfig`:

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    signing_secret="dedicated-signing-key",
))
```

### signing_token_lifetime

`AuthConfig` also exposes `signing_token_lifetime` (default: **86400** seconds,
i.e. 24 hours). This is a convenience value you can reference in your application
code when calling `verify_token` or `unsign_with_timestamp`:

```python
from tortoise_auth.config import get_config
from tortoise_auth.signing import verify_token

config = get_config()
original = verify_token(token, max_age=config.signing_token_lifetime)
```

| Setting                  | Type  | Default   | Description                              |
|--------------------------|-------|-----------|------------------------------------------|
| `signing_secret`         | `str` | `""`      | Dedicated HMAC key for signing.          |
| `signing_token_lifetime` | `int` | `86400`   | Default max age in seconds (24 hours).   |

---

## Error handling

All signing errors inherit from `SigningError`, which itself inherits from the
library's root exception `TortoiseAuthError`.

```text
TortoiseAuthError
  +-- SigningError
        +-- BadSignatureError
        +-- SignatureExpiredError
```

### BadSignatureError

Raised when:

- The separator is missing from the signed string.
- The HMAC signature does not match the expected value.
- The embedded timestamp cannot be decoded.

### SignatureExpiredError

Raised when:

- The token's age exceeds the `max_age` limit.
- The embedded timestamp is in the future (clock skew protection).

Both exceptions are importable from `tortoise_auth.exceptions`:

```python
from tortoise_auth.exceptions import BadSignatureError, SignatureExpiredError
```

!!! note
    Catching `SigningError` is sufficient if you want a single handler for all
    signing-related failures.

---

## Use cases

### Email verification

Generate a signed token containing the user ID, embed it in a verification URL,
and verify it when the user clicks the link.

```python
from tortoise_auth.signing import make_token, verify_token
from tortoise_auth.exceptions import BadSignatureError, SignatureExpiredError

# On registration
token = make_token(f"verify-email:{user.id}")
url = f"https://app.example.com/verify?token={token}"
# Send url to user via email...

# On click
try:
    value = verify_token(token, max_age=86400)  # 24 hours
    _, user_id = value.rsplit(":", 1)
    # Mark user as verified...
except (BadSignatureError, SignatureExpiredError):
    # Show error page
    ...
```

### Password reset

```python
# Generate reset link
token = make_token(f"password-reset:{user.id}")
url = f"https://app.example.com/reset?token={token}"

# Verify when the user submits a new password
try:
    value = verify_token(token, max_age=3600)  # 1 hour
    _, user_id = value.rsplit(":", 1)
    # Update password...
except SignatureExpiredError:
    # "This reset link has expired. Please request a new one."
    ...
except BadSignatureError:
    # "This reset link is invalid."
    ...
```

### Invite links

```python
# Create invite
token = make_token(f"invite:{org.id}:{role}")

# Verify (generous expiration for invites)
value = verify_token(token, max_age=604800)  # 7 days
_, org_id, role = value.split(":")
```

### Unsubscribe links

When you do not need expiration, use `Signer` directly for a shorter token:

```python
from tortoise_auth.signing import Signer

signer = Signer()
signed = signer.sign(f"unsubscribe:{user.id}")
url = f"https://app.example.com/unsubscribe?sig={signed}"

# On click
user_id = signer.unsign(signed).split(":")[1]
```

---

## API summary

| Function / Class                         | Description                                      |
|------------------------------------------|--------------------------------------------------|
| `make_token(value, secret="")`           | Create a timestamped signed token.               |
| `verify_token(token, *, max_age, secret)` | Verify a timestamped token and return the value. |
| `Signer(secret, *, separator)`           | Low-level HMAC-SHA256 signer.                    |
| `Signer.sign(value)`                     | Sign a value, returning `value:signature`.       |
| `Signer.unsign(signed_value)`            | Verify and return the original value.            |
| `TimestampSigner(secret, *, separator)`  | Signer with embedded timestamp support.          |
| `TimestampSigner.sign_with_timestamp(value)` | Sign a value with a Unix timestamp.         |
| `TimestampSigner.unsign_with_timestamp(signed_value, *, max_age)` | Verify signature and check expiration. |

---

Next step: learn how to react to authentication events with the [Events](events.md)
system.
