# Roadmap

An overview of what tortoise-auth ships today and where the project is headed.

---

## Current Status (v0.2.0)

The following features are implemented and available in the current release:

- **AbstractUser model** -- email field, password hashing, `is_active` and
  `is_verified` flags.
- **AuthService** -- high-level async API covering `login`, `authenticate`,
  `refresh`, `logout`, and `logout_all`.
- **Database token backend** -- server-side tokens stored in Tortoise ORM with
  SHA-256 hashing and full revocation support.
- **Password hashing** -- Argon2id (primary), Bcrypt, and PBKDF2-SHA256 with
  transparent auto-migration to the strongest hasher.
- **Password validation** -- four built-in validators (minimum length, common
  password list, numeric-only, user-attribute similarity) plus custom validators
  via the `PasswordValidator` Protocol.
- **HMAC signing** -- `Signer`, `TimestampSigner`, and convenience helpers
  `make_token` / `verify_token` for signed payloads.
- **Event system** -- async handlers for `user_login`, `user_login_failed`,
  `user_logout`, and `password_changed` events.
- **Global configuration** -- single `AuthConfig` dataclass to configure the
  entire library.

## Planned Features

These features are on the roadmap and under active consideration:

- **Email verification flow** -- built-in workflow for verifying user email
  addresses after registration.
- **Password reset flow** -- secure token-based password reset with configurable
  expiry.
- **API key authentication** -- long-lived keys for service-to-service or
  programmatic access.
- **TOTP / 2FA** -- time-based one-time passwords for two-factor authentication.
  The dependencies (`pyotp`, `qrcode`) are already included.
- **Rate limiting** -- configurable throttling for login attempts and other
  sensitive endpoints.
- **Framework integrations** -- first-party middleware and dependency injection
  for FastAPI, Starlette, and Litestar.

!!! note "No guarantees on ordering"
    The features above are listed roughly in order of priority, but timelines
    may shift based on community feedback and contributor availability.

## Contributing

Contributions, bug reports, and feature requests are welcome. Visit the
[GitHub repository](https://github.com/elie/tortoise-auth) to open an issue or
submit a pull request.
