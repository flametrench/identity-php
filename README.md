# flametrench/identity

[![CI](https://github.com/flametrench/identity-php/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/identity-php/actions/workflows/ci.yml)

Identity primitives for [Flametrench](https://flametrench.dev): users, credentials (Argon2id-pinned password + passkey + OIDC), user-bound sessions with rotation on refresh, and v0.2 multi-factor authentication ([ADR 0008](https://github.com/flametrench/spec/blob/main/decisions/0008-mfa.md), [ADR 0010](https://github.com/flametrench/spec/blob/main/decisions/0010-webauthn-rs256-eddsa.md)) — TOTP (RFC 6238), recovery codes, and WebAuthn assertion verification across ES256 / RS256 / EdDSA.

The PHP counterpart of [`@flametrench/identity`](https://github.com/flametrench/node/tree/main/packages/identity). Same shapes, same lifecycle, same Argon2id parameter floor, same opaque-bearer-token-vs-session-id distinction.

**Status:** v0.2.0 (stable). PHP 8.3+, ext-sodium required (for token base64url encoding). Includes the production-ready `PostgresIdentityStore` alongside the in-memory reference store. Per ADR 0014 the `User` entity carries an optional `display_name` with a partial-update `updateUser` operation; per ADR 0015 `listUsers` provides cursor-paginated user enumeration with a credential-identifier substring filter; per ADR 0013 the Postgres adapter cooperates with adopter-side outer transactions via savepoints when nested.

## Install

```bash
composer require flametrench/identity
```

## Quick start

```php
use Flametrench\Identity\InMemoryIdentityStore;

$store = new InMemoryIdentityStore();

// Create a user + a password credential.
$user = $store->createUser();
$cred = $store->createPasswordCredential($user->id, 'alice@example.com', 'correcthorsebatterystaple');

// Verify and open a session.
$verified = $store->verifyPassword('alice@example.com', 'correcthorsebatterystaple');
$sw = $store->createSession($verified->usrId, $verified->credId, ttlSeconds: 3600);

// Later, verify an incoming bearer token.
$session = $store->verifySessionToken($sw->token);
```

## Argon2id is pinned

Password credentials use PHP's native `PASSWORD_ARGON2ID` at the spec floor (`m=19456, t=2, p=1`). These match the OWASP Password Storage Cheat Sheet floor and are the same parameters used by `@flametrench/identity`. Implementations MUST NOT use bcrypt, scrypt, PBKDF2, or any other algorithm — the spec is opinionated on this point because inconsistency causes breaches.

## Sessions: tokens vs. ids

The session `id` is an **identifier** (appears in logs, audit, admin). The bearer **token** is separate — 32 random bytes, base64url-encoded — and only the SHA-256 hash is persisted. The plaintext token is returned exactly once from `createSession` / `refreshSession` and never leaves the caller's control via this SDK. Same separation as the spec defines.

`refreshSession` rotates: new session id, new token, old session revoked. In-place refresh is not spec-conformant.

## Credential type discrimination

PHP doesn't have discriminated unions, so credentials are three concrete classes implementing the `Credential` interface:

```php
$cred = $store->getCredential($credId);
match (true) {
    $cred instanceof PasswordCredential => /* ... */,
    $cred instanceof PasskeyCredential  => /* ... */,
    $cred instanceof OidcCredential     => /* ... */,
};
```

Sensitive material (password hash, passkey public key bytes) is stored internally and never exposed on the public Credential shape — verification uses `verifyPassword()` and never returns hash material to callers.

## Errors

| Class | Code |
|---|---|
| `NotFoundException` | `not_found` |
| `DuplicateCredentialException` | `conflict.duplicate_credential` |
| `InvalidCredentialException` | `unauthorized.invalid_credential` |
| `CredentialNotActiveException` | `conflict.credential_not_active` |
| `CredentialTypeMismatchException` | `conflict.credential_type_mismatch` |
| `SessionExpiredException` | `unauthorized.session_expired` |
| `InvalidTokenException` | `unauthorized.invalid_token` |
| `AlreadyTerminalException` | `conflict.already_terminal` |
| `PreconditionException` | `precondition.<specifics>` |

## Cascade semantics (spec-required)

- **Revoking a user** revokes every active credential AND terminates every active session.
- **Suspending a user** terminates every active session but leaves credentials alone (the user can be reinstated and their creds still work).
- **Rotating a credential** terminates every session that was established by the old credential.
- **Suspending or revoking a credential** terminates every session bound to it.

All cascades are atomic in the in-memory store; tests have explicit fixtures for each.

## Development

```bash
composer install
composer test
```

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
