# Installation

## Requirements

Before installing `tortoise-auth`, make sure your environment meets the following minimum
requirements:

| Dependency      | Minimum version |
|-----------------|-----------------|
| Python          | 3.12+           |
| Tortoise ORM    | 0.21+           |

!!! note
    `tortoise-auth` uses modern Python features such as type aliases, `type` statements,
    and generic built-in types that require **Python 3.12 or later**.

## Install tortoise-auth

=== "pip"

    ```bash
    pip install tortoise-auth
    ```

=== "uv"

    ```bash
    uv add tortoise-auth
    ```

## Transitive dependencies

When you install `tortoise-auth`, the following packages are pulled in automatically.
You do **not** need to install them separately.

| Package                   | Purpose                                                                                              |
|---------------------------|------------------------------------------------------------------------------------------------------|
| `tortoise-orm` >=0.21    | Async ORM built on top of `asyncio`. Provides the model layer that `tortoise-auth` extends.          |
| `pwdlib[argon2,bcrypt]` >=0.2 | Password hashing library. Includes the **Argon2** and **bcrypt** backends out of the box.       |
| `PyJWT` >=2.8            | Encoding and decoding of JSON Web Tokens (JWT) for stateless authentication.                         |
| `pyotp` >=2.9            | One-time password generation and verification for TOTP-based two-factor authentication.              |
| `qrcode[pil]` >=7.4      | QR code generation used when setting up TOTP with authenticator apps.                                |

## Database driver

Tortoise ORM requires an async database driver. `tortoise-auth` does not bundle one because the
choice depends on which database you use in your project.

Install the driver that matches your database:

=== "SQLite (development)"

    ```bash
    pip install aiosqlite
    ```

=== "PostgreSQL"

    ```bash
    pip install asyncpg
    ```

=== "MySQL / MariaDB"

    ```bash
    pip install asyncmy
    ```

!!! warning
    SQLite is convenient for local development and testing, but it is **not recommended for
    production**. Use PostgreSQL or MySQL for production deployments.

## Verify the installation

Open a Python shell and confirm that the package is importable and reports the expected version:

```python
import tortoise_auth

print(tortoise_auth.__version__)
```

You should see output similar to:

```text
0.1.0
```

!!! tip
    If the import fails with a `ModuleNotFoundError`, make sure you are running the Python
    interpreter from the same virtual environment where you installed the package.

---

Next step: head over to the [Quick Start](quickstart.md) guide to configure `tortoise-auth` and
create your first user.
