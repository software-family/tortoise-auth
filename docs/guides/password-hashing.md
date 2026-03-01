# Password Hashing

tortoise-auth ships a multi-algorithm password hashing stack built on top of
[pwdlib](https://github.com/frankie567/pwdlib). Newly created passwords are
always hashed with **Argon2id** -- the current industry recommendation -- while
older hashes produced by Bcrypt or PBKDF2-SHA256 are verified transparently and
automatically migrated to Argon2id on the next successful login.

---

## Hasher stack

The hasher stack is an ordered list of algorithms. The **first** entry is the
*primary* hasher -- the one used to create new hashes. The remaining entries are
*migration* hashers -- they can verify existing hashes but are never used to
create new ones.

| Position | Algorithm      | Role      | Hash prefix / identifier          |
|----------|----------------|-----------|-----------------------------------|
| 1        | Argon2id       | Primary   | `$argon2id$`                      |
| 2        | Bcrypt         | Migration | `$2b$`                            |
| 3        | PBKDF2-SHA256  | Migration | `pbkdf2_sha256$`                  |

When `check_password` encounters a valid hash from a migration hasher, it
re-hashes the plaintext with Argon2id and returns the updated hash so the caller
can persist it. This is what powers **automatic hash migration**.

---

## How it works

### Hashing a new password

```python
from tortoise_auth.hashers import make_password

hashed = make_password("my-secret-password")
# Returns an Argon2id hash string, e.g. "$argon2id$v=19$m=65536,t=3,p=4$..."
```

`make_password` is a convenience wrapper that builds a `PasswordHash` instance
with the default parameters and calls its `.hash()` method. It always uses the
primary hasher (Argon2id).

### Verifying a password

```python
from tortoise_auth.hashers import check_password

valid, updated_hash = check_password("my-secret-password", hashed)
```

`check_password` returns a tuple of `(bool, str | None)`:

- **`valid`** -- `True` if the plaintext matches the stored hash.
- **`updated_hash`** -- a new Argon2id hash string if the original hash was
  produced by a non-primary algorithm (Bcrypt, PBKDF2) or with outdated
  parameters. `None` if no re-hash is needed.

When `updated_hash` is not `None`, you should persist it to the database so
subsequent checks use the stronger hash.

### The AbstractUser shortcut

If you extend `AbstractUser`, you do not need to call these functions directly.
The model provides async methods that handle hashing, verification, and
migration internally:

```python
# Hash and save a new password (emits a "password_changed" event)
await user.set_password("new-password")

# Verify against the stored hash -- auto-migrates if needed
is_valid = await user.check_password("new-password")
```

`AbstractUser.check_password` automatically persists the migrated hash to the
database when an upgrade is detected. No additional code is required.

---

## Auto-migration

Auto-migration is the process of transparently upgrading a password hash from a
weaker or outdated algorithm to the primary hasher. It happens inside
`check_password` (and `AbstractUser.check_password`) during a successful
password verification.

The migration flow:

1. The user submits their plaintext password at login time.
2. `check_password` identifies the algorithm from the stored hash prefix.
3. The correct hasher verifies the plaintext against the stored hash.
4. If verification succeeds **and** the hash was not produced by the primary
   hasher (or uses outdated parameters), `pwdlib` re-hashes the plaintext with
   Argon2id and returns it as `updated_hash`.
5. The caller (or `AbstractUser.check_password`) saves the new hash.

After this single login, all future checks for that user run against Argon2id.

!!! note
    Migration only occurs on **successful** verification. A failed login attempt
    does not trigger a re-hash.

### Example: migrating a Bcrypt hash

```python
from tortoise_auth.hashers.bcrypt import default_hasher as bcrypt_default
from tortoise_auth.hashers import check_password

# Simulate an existing Bcrypt hash from a legacy system
bcrypt_hasher = bcrypt_default(rounds=10)
legacy_hash = bcrypt_hasher.hash("old-password")

# Verify and get the migrated Argon2id hash
valid, upgraded = check_password("old-password", legacy_hash)

assert valid is True
assert upgraded is not None         # New Argon2id hash
assert upgraded.startswith("$argon2id$")
```

---

## Tuning parameters

Every algorithm in the stack exposes tuning parameters that control the
computational cost of hashing. Higher costs improve resistance to brute-force
attacks but increase the time each hash operation takes.

### Defaults

| Parameter              | Default     | Algorithm     | Description                                |
|------------------------|-------------|---------------|--------------------------------------------|
| `argon2_time_cost`     | `3`         | Argon2id      | Number of iterations (passes over memory). |
| `argon2_memory_cost`   | `65536`     | Argon2id      | Memory usage in KiB (64 MB).               |
| `argon2_parallelism`   | `4`         | Argon2id      | Number of parallel threads.                |
| `bcrypt_rounds`        | `12`        | Bcrypt        | Log2 of the work factor.                   |
| `pbkdf2_iterations`    | `600,000`   | PBKDF2-SHA256 | Number of HMAC-SHA256 iterations.          |

These defaults follow the [OWASP password storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
recommendations.

### Configuring via AuthConfig

Pass the desired values when you create your `AuthConfig`:

```python
from tortoise_auth import AuthConfig, configure

configure(AuthConfig(
    user_model="models.User",

    # Increase Argon2 cost for high-security environments
    argon2_time_cost=4,
    argon2_memory_cost=131072,   # 128 MB
    argon2_parallelism=8,

    # Bcrypt and PBKDF2 are only used for verifying legacy hashes
    bcrypt_rounds=12,
    pbkdf2_iterations=600_000,
))

When you change the Argon2 parameters, existing Argon2 hashes that were created
with the old parameters will be detected as needing a re-hash (via
`check_needs_rehash`). The next successful login will transparently upgrade them
to the new cost settings.

### Configuring via default_password_hash

For standalone usage outside the `AuthConfig` system, you can build a
`PasswordHash` instance directly:

```python
from tortoise_auth.hashers import default_password_hash

ph = default_password_hash(
    argon2_time_cost=4,
    argon2_memory_cost=131072,
    argon2_parallelism=8,
)

hashed = ph.hash("my-password")
valid, updated = ph.verify_and_update("my-password", hashed)
```

---

## Supported algorithms and formats

### Argon2id

- **Library**: `argon2-cffi` (via `pwdlib`)
- **Hash format**: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`
- **Identifier**: Hashes start with `$argon2id$`
- **Status**: Primary hasher -- all new passwords are hashed with Argon2id

Argon2id is a memory-hard key derivation function that won the
[Password Hashing Competition](https://www.password-hashing.net/) in 2015. The
"id" variant combines the side-channel resistance of Argon2i with the GPU
resistance of Argon2d.

### Bcrypt

- **Library**: `bcrypt` (via `pwdlib`)
- **Hash format**: `$2b$12$<22-char-salt><31-char-hash>`
- **Identifier**: Hashes start with `$2b$`
- **Status**: Migration hasher -- existing Bcrypt hashes are verified and
  migrated to Argon2id

### PBKDF2-SHA256

- **Library**: Python standard library (`hashlib.pbkdf2_hmac`)
- **Hash format**: `pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>`
- **Identifier**: Hashes start with `pbkdf2_sha256$`
- **Status**: Migration hasher -- existing PBKDF2 hashes are verified and
  migrated to Argon2id

The `PBKDF2Hasher` is a custom implementation that conforms to pwdlib's
`HasherProtocol`. It uses HMAC-SHA256 with a 16-byte random salt and
constant-time comparison via `hmac.compare_digest`.

---

## Migration from Django

If you are migrating an application from Django's authentication system,
tortoise-auth can verify your existing password hashes without any conversion
step.

Django's default hasher produces hashes in the format:

```text
pbkdf2_sha256$<iterations>$<salt>$<hash>
```

tortoise-auth's `PBKDF2Hasher` recognizes this format. When a user logs in with
a Django-originated PBKDF2 hash:

1. The PBKDF2 hasher identifies and verifies the hash.
2. Because PBKDF2 is a migration hasher, `check_password` returns an Argon2id
   `updated_hash`.
3. `AbstractUser.check_password` persists the new Argon2id hash to the database.

After a single successful login, the user's password is stored as Argon2id. No
batch migration script is needed -- the upgrade happens organically as users
authenticate.

!!! note "Django salt encoding"
    Django stores the salt as a raw string, while tortoise-auth's `PBKDF2Hasher`
    uses base64-encoded salts. If your existing Django hashes use the standard
    Django format, you may need to verify compatibility with a test login before
    relying on automatic migration. The safest approach is to test a known
    password against an exported hash from your Django database.

---

## Unusable passwords

tortoise-auth supports the concept of an *unusable password* for accounts that
should not authenticate via password (for example, OAuth-only users).

```python
# Mark a user as having no usable password
user.set_unusable_password()
assert not user.has_usable_password()

# check_password always returns False for unusable passwords
assert not await user.check_password("anything")
```

An unusable password is a random string prefixed with `!`. Since no hasher
produces hashes with this prefix, verification always fails.

---

## Standalone functions reference

All public functions and classes are importable from `tortoise_auth.hashers`:

```python
from tortoise_auth.hashers import (
    Argon2Hasher,
    BcryptHasher,
    HasherProtocol,
    PBKDF2Hasher,
    PasswordHash,
    check_password,
    default_password_hash,
    make_password,
)
```

### `make_password(password) -> str`

Hash a plaintext password using the primary hasher (Argon2id) with default
parameters. Returns the hash string.

### `check_password(password, hashed) -> tuple[bool, str | None]`

Verify a plaintext password against a stored hash. Returns a tuple where the
first element indicates whether the password is valid, and the second element
contains an updated Argon2id hash if migration is needed (`None` otherwise).

### `default_password_hash(**kwargs) -> PasswordHash`

Build a `PasswordHash` instance with the full hasher stack (Argon2id, Bcrypt,
PBKDF2). Accepts optional keyword arguments to override the default tuning
parameters:

- `argon2_time_cost` (default: `3`)
- `argon2_memory_cost` (default: `65536`)
- `argon2_parallelism` (default: `4`)
- `bcrypt_rounds` (default: `12`)
- `pbkdf2_iterations` (default: `600_000`)

The returned `PasswordHash` object exposes `.hash()` and
`.verify_and_update()` methods from pwdlib.

---

## Security considerations

- **Always use the highest cost you can tolerate.** Hashing costs should be
  tuned so that a single hash operation takes between 200ms and 500ms on your
  production hardware.
- **Never store plaintext passwords.** Use `make_password` or
  `AbstractUser.set_password` for every password that enters the system.
- **Persist migrated hashes.** When `check_password` returns an `updated_hash`,
  save it. Skipping this step means the user stays on the weaker algorithm
  indefinitely.
- **Do not lower Argon2 costs in production.** Reducing `argon2_time_cost` or
  `argon2_memory_cost` weakens the protection for all newly hashed passwords.
  Only lower costs for testing or development environments.
- **Monitor hash operation latency.** If your login endpoint latency increases
  after tuning, consider whether the cost increase is justified or if you need
  to scale your infrastructure.
