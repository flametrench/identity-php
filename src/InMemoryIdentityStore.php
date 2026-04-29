<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

use Flametrench\Identity\Exceptions\AlreadyTerminalException;
use Flametrench\Identity\Exceptions\CredentialNotActiveException;
use Flametrench\Identity\Exceptions\CredentialTypeMismatchException;
use Flametrench\Identity\Exceptions\DuplicateCredentialException;
use Flametrench\Identity\Exceptions\InvalidCredentialException;
use Flametrench\Identity\Exceptions\InvalidTokenException;
use Flametrench\Identity\Exceptions\NotFoundException;
use Flametrench\Identity\Exceptions\PreconditionException;
use Flametrench\Identity\Exceptions\SessionExpiredException;
use Flametrench\Ids\Id;

/**
 * Reference in-memory IdentityStore.
 *
 * Argon2id passwords use PHP's native PASSWORD_ARGON2ID at the spec floor
 * (m=19456, t=2, p=1). Bearer tokens are 32 random bytes, base64url-
 * encoded; only the SHA-256 hash is persisted, never the token itself.
 *
 * Internally tracks public Credential objects alongside type-specific
 * sensitive material (password hashes, passkey public keys) in separate
 * arrays so the public surface never leaks them.
 */
final class InMemoryIdentityStore implements IdentityStore
{
    public const UNSET = IdentityStore::UNSET;

    /** @var array<string, User> */
    private array $users = [];

    /** @var array<string, Credential> Public credential entities. */
    private array $credentials = [];

    /** @var array<string, string> credId → PHC-encoded password hash. */
    private array $passwordHashes = [];

    /** @var array<string, string> credId → raw passkey public key bytes. */
    private array $passkeyPublicKeys = [];

    /** @var array<string, string> "type|identifier" → credId (active only). */
    private array $activeCredByIdentifier = [];

    /** @var array<string, Session> */
    private array $sessions = [];

    /** @var array<string, string> sesId → SHA-256 hex of bearer token. */
    private array $sessionTokenHashes = [];

    /** @var array<string, string> token-hash → sesId. */
    private array $sessionByTokenHash = [];

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    public function __construct(?callable $clock = null)
    {
        $this->clock = $clock ?? static fn(): \DateTimeImmutable => new \DateTimeImmutable();
    }

    private function now(): \DateTimeImmutable
    {
        return ($this->clock)();
    }

    private function identifierKey(CredentialType $type, string $identifier): string
    {
        return "{$type->value}|{$identifier}";
    }

    private function requireUser(string $usrId): User
    {
        return $this->users[$usrId] ?? throw new NotFoundException("User {$usrId} not found");
    }

    private function requireCredential(string $credId): Credential
    {
        return $this->credentials[$credId] ?? throw new NotFoundException("Credential {$credId} not found");
    }

    private function requireSession(string $sesId): Session
    {
        return $this->sessions[$sesId] ?? throw new NotFoundException("Session {$sesId} not found");
    }

    private function cascadeRevokeSessionsForCredential(string $credId): void
    {
        $now = $this->now();
        foreach ($this->sessions as $sesId => $ses) {
            if ($ses->credId === $credId && $ses->revokedAt === null) {
                $this->sessions[$sesId] = $ses->withRevokedAt($now);
                if (isset($this->sessionTokenHashes[$sesId])) {
                    unset($this->sessionByTokenHash[$this->sessionTokenHashes[$sesId]]);
                    unset($this->sessionTokenHashes[$sesId]);
                }
            }
        }
    }

    private function cascadeRevokeSessionsForUser(string $usrId): void
    {
        $now = $this->now();
        foreach ($this->sessions as $sesId => $ses) {
            if ($ses->usrId === $usrId && $ses->revokedAt === null) {
                $this->sessions[$sesId] = $ses->withRevokedAt($now);
                if (isset($this->sessionTokenHashes[$sesId])) {
                    unset($this->sessionByTokenHash[$this->sessionTokenHashes[$sesId]]);
                    unset($this->sessionTokenHashes[$sesId]);
                }
            }
        }
    }

    // ─── Users ───

    public function createUser(?string $displayName = null): User
    {
        $now = $this->now();
        $u = new User(
            id: Id::generate('usr'),
            status: Status::Active,
            createdAt: $now,
            updatedAt: $now,
            displayName: $displayName,
        );
        $this->users[$u->id] = $u;
        return $u;
    }

    public function getUser(string $usrId): User
    {
        return $this->requireUser($usrId);
    }

    public function updateUser(
        string $usrId,
        string|null $displayName = self::UNSET,
    ): User {
        $u = $this->requireUser($usrId);
        if ($u->status === Status::Revoked) {
            throw new AlreadyTerminalException(
                "User {$usrId} is revoked; cannot update",
            );
        }
        $newDisplayName = $displayName === self::UNSET ? $u->displayName : $displayName;
        if ($newDisplayName === $u->displayName) {
            return $u;
        }
        $updated = new User(
            id: $u->id,
            status: $u->status,
            createdAt: $u->createdAt,
            updatedAt: $this->now(),
            displayName: $newDisplayName,
        );
        $this->users[$usrId] = $updated;
        return $updated;
    }

    public function suspendUser(string $usrId): User
    {
        $u = $this->requireUser($usrId);
        if ($u->status === Status::Revoked) {
            throw new AlreadyTerminalException("User {$usrId} is revoked");
        }
        if ($u->status === Status::Suspended) return $u;
        $now = $this->now();
        $updated = $u->withStatus(Status::Suspended, $now);
        $this->users[$usrId] = $updated;
        $this->cascadeRevokeSessionsForUser($usrId);
        return $updated;
    }

    public function reinstateUser(string $usrId): User
    {
        $u = $this->requireUser($usrId);
        if ($u->status !== Status::Suspended) {
            throw new PreconditionException(
                "User {$usrId} is {$u->status->value}; only suspended users can be reinstated",
                'invalid_transition',
            );
        }
        $updated = $u->withStatus(Status::Active, $this->now());
        $this->users[$usrId] = $updated;
        return $updated;
    }

    public function revokeUser(string $usrId): User
    {
        $u = $this->requireUser($usrId);
        if ($u->status === Status::Revoked) {
            throw new AlreadyTerminalException("User {$usrId} is already revoked");
        }
        $now = $this->now();
        // Cascade: revoke active credentials.
        foreach ($this->credentials as $credId => $cred) {
            if ($cred->getUsrId() === $usrId && $cred->getStatus() === Status::Active) {
                $this->credentials[$credId] = $this->withCredentialStatus($cred, Status::Revoked, $now);
                unset($this->activeCredByIdentifier[$this->identifierKey($cred->getType(), $cred->getIdentifier())]);
            }
        }
        $this->cascadeRevokeSessionsForUser($usrId);
        $updated = $u->withStatus(Status::Revoked, $now);
        $this->users[$usrId] = $updated;
        return $updated;
    }

    // ─── Credentials ───

    private function withCredentialStatus(
        Credential $cred,
        Status $status,
        \DateTimeImmutable $updatedAt,
    ): Credential {
        return match (true) {
            $cred instanceof PasswordCredential => new PasswordCredential(
                $cred->id, $cred->usrId, $cred->identifier, $status, $cred->replaces, $cred->createdAt, $updatedAt,
            ),
            $cred instanceof PasskeyCredential => new PasskeyCredential(
                $cred->id, $cred->usrId, $cred->identifier, $status, $cred->replaces,
                $cred->passkeySignCount, $cred->passkeyRpId, $cred->createdAt, $updatedAt,
            ),
            $cred instanceof OidcCredential => new OidcCredential(
                $cred->id, $cred->usrId, $cred->identifier, $status, $cred->replaces,
                $cred->oidcIssuer, $cred->oidcSubject, $cred->createdAt, $updatedAt,
            ),
            default => throw new \LogicException('Unknown credential type'),
        };
    }

    private function ensureUserActiveAndUniqueIdentifier(
        string $usrId,
        CredentialType $type,
        string $identifier,
    ): void {
        $user = $this->requireUser($usrId);
        if ($user->status !== Status::Active) {
            throw new PreconditionException(
                "Cannot create credentials for {$user->status->value} user",
                'user_not_active',
            );
        }
        if (isset($this->activeCredByIdentifier[$this->identifierKey($type, $identifier)])) {
            throw new DuplicateCredentialException(
                "An active {$type->value} credential already exists for identifier {$identifier}",
            );
        }
    }

    public function createPasswordCredential(
        string $usrId,
        string $identifier,
        string $password,
    ): PasswordCredential {
        $this->ensureUserActiveAndUniqueIdentifier($usrId, CredentialType::Password, $identifier);
        $now = $this->now();
        $id = Id::generate('cred');
        $hash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => Argon2id::MEMORY_COST,
            'time_cost' => Argon2id::TIME_COST,
            'threads' => Argon2id::THREADS,
        ]);
        $cred = new PasswordCredential(
            id: $id,
            usrId: $usrId,
            identifier: $identifier,
            status: Status::Active,
            replaces: null,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->credentials[$id] = $cred;
        $this->passwordHashes[$id] = $hash;
        $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Password, $identifier)] = $id;
        return $cred;
    }

    public function createPasskeyCredential(
        string $usrId,
        string $identifier,
        string $publicKey,
        int $signCount,
        string $rpId,
    ): PasskeyCredential {
        $this->ensureUserActiveAndUniqueIdentifier($usrId, CredentialType::Passkey, $identifier);
        $now = $this->now();
        $id = Id::generate('cred');
        $cred = new PasskeyCredential(
            id: $id,
            usrId: $usrId,
            identifier: $identifier,
            status: Status::Active,
            replaces: null,
            passkeySignCount: $signCount,
            passkeyRpId: $rpId,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->credentials[$id] = $cred;
        $this->passkeyPublicKeys[$id] = $publicKey;
        $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Passkey, $identifier)] = $id;
        return $cred;
    }

    public function createOidcCredential(
        string $usrId,
        string $identifier,
        string $oidcIssuer,
        string $oidcSubject,
    ): OidcCredential {
        $this->ensureUserActiveAndUniqueIdentifier($usrId, CredentialType::Oidc, $identifier);
        $now = $this->now();
        $id = Id::generate('cred');
        $cred = new OidcCredential(
            id: $id,
            usrId: $usrId,
            identifier: $identifier,
            status: Status::Active,
            replaces: null,
            oidcIssuer: $oidcIssuer,
            oidcSubject: $oidcSubject,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->credentials[$id] = $cred;
        $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Oidc, $identifier)] = $id;
        return $cred;
    }

    public function getCredential(string $credId): Credential
    {
        return $this->requireCredential($credId);
    }

    public function listCredentialsForUser(string $usrId): array
    {
        return array_values(array_filter(
            $this->credentials,
            fn(Credential $c) => $c->getUsrId() === $usrId,
        ));
    }

    public function findCredentialByIdentifier(CredentialType $type, string $identifier): ?Credential
    {
        $credId = $this->activeCredByIdentifier[$this->identifierKey($type, $identifier)] ?? null;
        return $credId === null ? null : $this->requireCredential($credId);
    }

    public function rotatePassword(string $credId, string $newPassword): PasswordCredential
    {
        $old = $this->requireCredential($credId);
        if ($old->getStatus() !== Status::Active) {
            throw new CredentialNotActiveException("Credential {$credId} is {$old->getStatus()->value}");
        }
        if (!$old instanceof PasswordCredential) {
            throw new CredentialTypeMismatchException(
                "Cannot rotate {$old->getType()->value} credential as password",
            );
        }
        $now = $this->now();
        // Revoke old.
        $this->credentials[$old->id] = $this->withCredentialStatus($old, Status::Revoked, $now);
        unset($this->activeCredByIdentifier[$this->identifierKey(CredentialType::Password, $old->identifier)]);
        unset($this->passwordHashes[$old->id]);
        $this->cascadeRevokeSessionsForCredential($old->id);
        // Insert new.
        $newId = Id::generate('cred');
        $hash = password_hash($newPassword, PASSWORD_ARGON2ID, [
            'memory_cost' => Argon2id::MEMORY_COST,
            'time_cost' => Argon2id::TIME_COST,
            'threads' => Argon2id::THREADS,
        ]);
        $fresh = new PasswordCredential(
            id: $newId,
            usrId: $old->usrId,
            identifier: $old->identifier,
            status: Status::Active,
            replaces: $old->id,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->credentials[$newId] = $fresh;
        $this->passwordHashes[$newId] = $hash;
        $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Password, $old->identifier)] = $newId;
        return $fresh;
    }

    public function rotatePasskey(string $credId, string $publicKey, int $signCount, string $rpId): PasskeyCredential
    {
        $old = $this->requireCredential($credId);
        if ($old->getStatus() !== Status::Active) {
            throw new CredentialNotActiveException("Credential {$credId} is {$old->getStatus()->value}");
        }
        if (!$old instanceof PasskeyCredential) {
            throw new CredentialTypeMismatchException(
                "Cannot rotate {$old->getType()->value} credential as passkey",
            );
        }
        $now = $this->now();
        $this->credentials[$old->id] = $this->withCredentialStatus($old, Status::Revoked, $now);
        unset($this->activeCredByIdentifier[$this->identifierKey(CredentialType::Passkey, $old->identifier)]);
        unset($this->passkeyPublicKeys[$old->id]);
        $this->cascadeRevokeSessionsForCredential($old->id);
        $newId = Id::generate('cred');
        $fresh = new PasskeyCredential(
            id: $newId,
            usrId: $old->usrId,
            identifier: $old->identifier,
            status: Status::Active,
            replaces: $old->id,
            passkeySignCount: $signCount,
            passkeyRpId: $rpId,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->credentials[$newId] = $fresh;
        $this->passkeyPublicKeys[$newId] = $publicKey;
        $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Passkey, $old->identifier)] = $newId;
        return $fresh;
    }

    public function rotateOidc(string $credId, string $oidcIssuer, string $oidcSubject): OidcCredential
    {
        $old = $this->requireCredential($credId);
        if ($old->getStatus() !== Status::Active) {
            throw new CredentialNotActiveException("Credential {$credId} is {$old->getStatus()->value}");
        }
        if (!$old instanceof OidcCredential) {
            throw new CredentialTypeMismatchException(
                "Cannot rotate {$old->getType()->value} credential as oidc",
            );
        }
        $now = $this->now();
        $this->credentials[$old->id] = $this->withCredentialStatus($old, Status::Revoked, $now);
        unset($this->activeCredByIdentifier[$this->identifierKey(CredentialType::Oidc, $old->identifier)]);
        $this->cascadeRevokeSessionsForCredential($old->id);
        $newId = Id::generate('cred');
        $fresh = new OidcCredential(
            id: $newId,
            usrId: $old->usrId,
            identifier: $old->identifier,
            status: Status::Active,
            replaces: $old->id,
            oidcIssuer: $oidcIssuer,
            oidcSubject: $oidcSubject,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->credentials[$newId] = $fresh;
        $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Oidc, $old->identifier)] = $newId;
        return $fresh;
    }

    public function suspendCredential(string $credId): Credential
    {
        $c = $this->requireCredential($credId);
        if ($c->getStatus() !== Status::Active) {
            throw new PreconditionException(
                "Credential {$credId} is {$c->getStatus()->value}; only active credentials can be suspended",
                'cred_not_active',
            );
        }
        $now = $this->now();
        $updated = $this->withCredentialStatus($c, Status::Suspended, $now);
        $this->credentials[$credId] = $updated;
        unset($this->activeCredByIdentifier[$this->identifierKey($c->getType(), $c->getIdentifier())]);
        $this->cascadeRevokeSessionsForCredential($credId);
        return $updated;
    }

    public function reinstateCredential(string $credId): Credential
    {
        $c = $this->requireCredential($credId);
        if ($c->getStatus() !== Status::Suspended) {
            throw new PreconditionException(
                "Credential {$credId} is {$c->getStatus()->value}; only suspended credentials can be reinstated",
                'invalid_transition',
            );
        }
        $key = $this->identifierKey($c->getType(), $c->getIdentifier());
        if (isset($this->activeCredByIdentifier[$key])) {
            throw new DuplicateCredentialException(
                "Another active {$c->getType()->value} credential already exists for {$c->getIdentifier()}; cannot reinstate",
            );
        }
        $now = $this->now();
        $updated = $this->withCredentialStatus($c, Status::Active, $now);
        $this->credentials[$credId] = $updated;
        $this->activeCredByIdentifier[$key] = $credId;
        return $updated;
    }

    public function revokeCredential(string $credId): Credential
    {
        $c = $this->requireCredential($credId);
        if ($c->getStatus() === Status::Revoked) {
            throw new AlreadyTerminalException("Credential {$credId} is already revoked");
        }
        $now = $this->now();
        $updated = $this->withCredentialStatus($c, Status::Revoked, $now);
        $this->credentials[$credId] = $updated;
        unset($this->activeCredByIdentifier[$this->identifierKey($c->getType(), $c->getIdentifier())]);
        $this->cascadeRevokeSessionsForCredential($credId);
        return $updated;
    }

    public function verifyPassword(string $identifier, string $password): VerifiedCredential
    {
        $credId = $this->activeCredByIdentifier[$this->identifierKey(CredentialType::Password, $identifier)] ?? null;
        if ($credId === null) {
            throw new InvalidCredentialException('Invalid credential');
        }
        $hash = $this->passwordHashes[$credId] ?? null;
        if ($hash === null || !password_verify($password, $hash)) {
            throw new InvalidCredentialException('Invalid credential');
        }
        $cred = $this->requireCredential($credId);
        // ADR 0008: surface usr_mfa_policy state.
        $policy = $this->mfaPolicies[$cred->getUsrId()] ?? null;
        $mfaRequired = false;
        if ($policy !== null && $policy->required) {
            if ($policy->graceUntil === null || $policy->graceUntil <= $this->now()) {
                $mfaRequired = true;
            }
        }
        return new VerifiedCredential(
            usrId: $cred->getUsrId(),
            credId: $cred->getId(),
            mfaRequired: $mfaRequired,
        );
    }

    // ─── Sessions ───

    private function generateToken(): string
    {
        return sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    private static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public function createSession(string $usrId, string $credId, int $ttlSeconds): SessionWithToken
    {
        $user = $this->requireUser($usrId);
        if ($user->status !== Status::Active) {
            throw new PreconditionException(
                "Cannot create session for {$user->status->value} user",
                'user_not_active',
            );
        }
        $cred = $this->requireCredential($credId);
        if ($cred->getStatus() !== Status::Active) {
            throw new CredentialNotActiveException("Credential {$credId} is {$cred->getStatus()->value}");
        }
        if ($cred->getUsrId() !== $usrId) {
            throw new PreconditionException(
                "Credential {$credId} does not belong to {$usrId}",
                'cred_user_mismatch',
            );
        }
        if ($ttlSeconds < 60) {
            throw new PreconditionException('ttlSeconds must be >= 60', 'ttl_too_short');
        }
        $now = $this->now();
        $token = $this->generateToken();
        $tokenHash = self::hashToken($token);
        $session = new Session(
            id: Id::generate('ses'),
            usrId: $usrId,
            credId: $credId,
            createdAt: $now,
            expiresAt: $now->modify("+{$ttlSeconds} seconds"),
            revokedAt: null,
        );
        $this->sessions[$session->id] = $session;
        $this->sessionTokenHashes[$session->id] = $tokenHash;
        $this->sessionByTokenHash[$tokenHash] = $session->id;
        return new SessionWithToken(session: $session, token: $token);
    }

    public function getSession(string $sesId): Session
    {
        return $this->requireSession($sesId);
    }

    public function listSessionsForUser(string $usrId, ?string $cursor = null, int $limit = 50): Page
    {
        $matching = array_values(array_filter(
            $this->sessions,
            fn(Session $s) => $s->usrId === $usrId,
        ));
        usort($matching, fn(Session $a, Session $b) => strcmp($a->id, $b->id));
        if ($cursor !== null) {
            $startIdx = 0;
            foreach ($matching as $i => $item) {
                if ($item->id > $cursor) { $startIdx = $i; break; }
                $startIdx = $i + 1;
            }
        } else {
            $startIdx = 0;
        }
        $slice = array_slice($matching, $startIdx, $limit);
        $next = ($startIdx + $limit) < count($matching) && count($slice) > 0
            ? $slice[count($slice) - 1]->id
            : null;
        return new Page(data: $slice, nextCursor: $next);
    }

    public function verifySessionToken(string $token): Session
    {
        $tokenHash = self::hashToken($token);
        $sesId = $this->sessionByTokenHash[$tokenHash] ?? null;
        if ($sesId === null) {
            throw new InvalidTokenException('Invalid token');
        }
        $session = $this->requireSession($sesId);
        $storedHash = $this->sessionTokenHashes[$sesId] ?? '';
        if (!hash_equals($tokenHash, $storedHash)) {
            throw new InvalidTokenException('Invalid token');
        }
        if ($session->revokedAt !== null) {
            throw new SessionExpiredException('Session is revoked');
        }
        if ($this->now() > $session->expiresAt) {
            throw new SessionExpiredException('Session has expired');
        }
        return $session;
    }

    public function refreshSession(string $sesId): SessionWithToken
    {
        $session = $this->requireSession($sesId);
        if ($session->revokedAt !== null) {
            throw new SessionExpiredException('Session is already revoked');
        }
        if ($this->now() > $session->expiresAt) {
            throw new SessionExpiredException('Session has expired');
        }
        $now = $this->now();
        $revoked = $session->withRevokedAt($now);
        $this->sessions[$sesId] = $revoked;
        $oldHash = $this->sessionTokenHashes[$sesId] ?? null;
        if ($oldHash !== null) {
            unset($this->sessionByTokenHash[$oldHash]);
            unset($this->sessionTokenHashes[$sesId]);
        }
        $ttlMs = $session->expiresAt->getTimestamp() - $session->createdAt->getTimestamp();
        $token = $this->generateToken();
        $tokenHash = self::hashToken($token);
        $fresh = new Session(
            id: Id::generate('ses'),
            usrId: $session->usrId,
            credId: $session->credId,
            createdAt: $now,
            expiresAt: $now->modify("+{$ttlMs} seconds"),
            revokedAt: null,
        );
        $this->sessions[$fresh->id] = $fresh;
        $this->sessionTokenHashes[$fresh->id] = $tokenHash;
        $this->sessionByTokenHash[$tokenHash] = $fresh->id;
        return new SessionWithToken(session: $fresh, token: $token);
    }

    public function revokeSession(string $sesId): Session
    {
        $session = $this->requireSession($sesId);
        if ($session->revokedAt !== null) return $session;
        $now = $this->now();
        $updated = $session->withRevokedAt($now);
        $this->sessions[$sesId] = $updated;
        $oldHash = $this->sessionTokenHashes[$sesId] ?? null;
        if ($oldHash !== null) {
            unset($this->sessionByTokenHash[$oldHash]);
            unset($this->sessionTokenHashes[$sesId]);
        }
        return $updated;
    }

    // ─── v0.2 MFA store operations (ADR 0008) ───

    /** Pending TOTP/WebAuthn factor TTL per ADR 0008 (10 minutes). */
    public const PENDING_FACTOR_TTL_SECONDS = 600;

    /** @var array<string, Mfa\TotpFactor|Mfa\WebAuthnFactor|Mfa\RecoveryFactor> */
    private array $mfaFactors = [];
    /** @var array<string, string> mfaId → raw secret bytes */
    private array $mfaTotpSecrets = [];
    /** @var array<string, string> mfaId → COSE pubkey bytes */
    private array $mfaWebauthnKeys = [];
    /** @var array<string, list<string>> mfaId → 10 PHC hashes */
    private array $mfaRecoveryHashes = [];
    /** @var array<string, list<bool>> parallel array of consumed flags */
    private array $mfaRecoveryConsumed = [];
    /** @var array<string, string> "{usrId}|{type}" → mfaId (totp + recovery only) */
    private array $mfaActiveSingleton = [];
    /** @var array<string, string> credential_id → mfaId (active webauthn) */
    private array $mfaWebauthnByCredentialId = [];
    /** @var array<string, Mfa\UserMfaPolicy> */
    private array $mfaPolicies = [];

    public function enrollTotpFactor(string $usrId, string $identifier): array
    {
        $this->checkUserActive($usrId);
        $this->enforceNoActiveSingleton($usrId, 'totp');
        $now = $this->now();
        $secret = Mfa\Totp::generateSecret();
        $mfaId = Id::generate('mfa');
        $factor = new Mfa\TotpFactor(
            id: $mfaId,
            usrId: $usrId,
            identifier: $identifier,
            status: Mfa\FactorStatus::Pending,
            replaces: null,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->mfaFactors[$mfaId] = $factor;
        $this->mfaTotpSecrets[$mfaId] = $secret;
        $secretB32 = rtrim(self::base32Encode($secret), '=');
        $otpauthUri = Mfa\Totp::otpauthUri($secret, $identifier, 'Flametrench');
        return ['factor' => $factor, 'secretB32' => $secretB32, 'otpauthUri' => $otpauthUri];
    }

    public function enrollWebAuthnFactor(
        string $usrId,
        string $identifier,
        string $publicKey,
        int $signCount,
        string $rpId,
        ?string $aaguid = null,
        ?array $transports = null,
    ): array {
        $this->checkUserActive($usrId);
        if (isset($this->mfaWebauthnByCredentialId[$identifier])) {
            throw new Exceptions\PreconditionException(
                "WebAuthn credential '{$identifier}' is already enrolled",
                'duplicate_webauthn_credential',
            );
        }
        $now = $this->now();
        $mfaId = Id::generate('mfa');
        $factor = new Mfa\WebAuthnFactor(
            id: $mfaId,
            usrId: $usrId,
            identifier: $identifier,
            status: Mfa\FactorStatus::Pending,
            replaces: null,
            rpId: $rpId,
            signCount: $signCount,
            createdAt: $now,
            updatedAt: $now,
        );
        $this->mfaFactors[$mfaId] = $factor;
        $this->mfaWebauthnKeys[$mfaId] = $publicKey;
        $this->mfaWebauthnByCredentialId[$identifier] = $mfaId;
        return ['factor' => $factor];
    }

    public function enrollRecoveryFactor(string $usrId): array
    {
        $this->checkUserActive($usrId);
        $this->enforceNoActiveSingleton($usrId, 'recovery');
        $now = $this->now();
        $codes = Mfa\RecoveryCodes::generateSet();
        $hashes = array_map(fn($c) => PasswordHashing::hash($c), $codes);
        $consumed = array_fill(0, count($codes), false);
        $mfaId = Id::generate('mfa');
        $factor = new Mfa\RecoveryFactor(
            id: $mfaId,
            usrId: $usrId,
            status: Mfa\FactorStatus::Active,
            replaces: null,
            createdAt: $now,
            updatedAt: $now,
            remaining: count($codes),
        );
        $this->mfaFactors[$mfaId] = $factor;
        $this->mfaRecoveryHashes[$mfaId] = $hashes;
        $this->mfaRecoveryConsumed[$mfaId] = $consumed;
        $this->mfaActiveSingleton["{$usrId}|recovery"] = $mfaId;
        return ['factor' => $factor, 'codes' => $codes];
    }

    public function getMfaFactor(string $mfaId): Mfa\TotpFactor|Mfa\WebAuthnFactor|Mfa\RecoveryFactor
    {
        return $this->requireFactor($mfaId);
    }

    public function listMfaFactors(string $usrId): array
    {
        return array_values(array_filter(
            $this->mfaFactors,
            fn($f) => $f->usrId === $usrId,
        ));
    }

    public function confirmTotpFactor(string $mfaId, string $code): Mfa\TotpFactor
    {
        $factor = $this->requireFactor($mfaId);
        if (!$factor instanceof Mfa\TotpFactor) {
            throw new Exceptions\CredentialTypeMismatchException(
                "Factor {$mfaId} is not totp"
            );
        }
        if ($factor->status !== Mfa\FactorStatus::Pending) {
            throw new Exceptions\PreconditionException(
                "Factor {$mfaId} is {$factor->status->value}; only pending factors confirm",
                'factor_not_pending',
            );
        }
        $this->checkPendingNotExpired($factor);
        $secret = $this->mfaTotpSecrets[$mfaId];
        if (!Mfa\Totp::verify($secret, $code, $this->now()->getTimestamp())) {
            throw new Exceptions\InvalidCredentialException('TOTP code did not verify');
        }
        $now = $this->now();
        $active = new Mfa\TotpFactor(
            id: $factor->id,
            usrId: $factor->usrId,
            identifier: $factor->identifier,
            status: Mfa\FactorStatus::Active,
            replaces: $factor->replaces,
            createdAt: $factor->createdAt,
            updatedAt: $now,
        );
        $this->mfaFactors[$mfaId] = $active;
        $this->mfaActiveSingleton["{$factor->usrId}|totp"] = $mfaId;
        return $active;
    }

    public function confirmWebAuthnFactor(
        string $mfaId,
        string $authenticatorData,
        string $clientDataJson,
        string $signature,
        string $expectedChallenge,
        string $expectedOrigin,
    ): Mfa\WebAuthnFactor {
        $factor = $this->requireFactor($mfaId);
        if (!$factor instanceof Mfa\WebAuthnFactor) {
            throw new Exceptions\CredentialTypeMismatchException(
                "Factor {$mfaId} is not webauthn"
            );
        }
        if ($factor->status !== Mfa\FactorStatus::Pending) {
            throw new Exceptions\PreconditionException(
                "Factor {$mfaId} is {$factor->status->value}; only pending factors confirm",
                'factor_not_pending',
            );
        }
        $this->checkPendingNotExpired($factor);
        $result = Mfa\WebAuthn::verifyAssertion(
            cosePublicKey: $this->mfaWebauthnKeys[$mfaId],
            storedSignCount: $factor->signCount,
            storedRpId: $factor->rpId,
            expectedChallenge: $expectedChallenge,
            expectedOrigin: $expectedOrigin,
            authenticatorData: $authenticatorData,
            clientDataJson: $clientDataJson,
            signature: $signature,
        );
        $now = $this->now();
        $active = new Mfa\WebAuthnFactor(
            id: $factor->id,
            usrId: $factor->usrId,
            identifier: $factor->identifier,
            status: Mfa\FactorStatus::Active,
            replaces: $factor->replaces,
            rpId: $factor->rpId,
            signCount: $result->newSignCount,
            createdAt: $factor->createdAt,
            updatedAt: $now,
        );
        $this->mfaFactors[$mfaId] = $active;
        return $active;
    }

    public function revokeMfaFactor(string $mfaId): Mfa\TotpFactor|Mfa\WebAuthnFactor|Mfa\RecoveryFactor
    {
        $factor = $this->requireFactor($mfaId);
        if ($factor->status === Mfa\FactorStatus::Revoked) return $factor;
        $now = $this->now();
        if ($factor instanceof Mfa\TotpFactor) {
            $revoked = new Mfa\TotpFactor(
                id: $factor->id, usrId: $factor->usrId, identifier: $factor->identifier,
                status: Mfa\FactorStatus::Revoked, replaces: $factor->replaces,
                createdAt: $factor->createdAt, updatedAt: $now,
            );
            unset($this->mfaActiveSingleton["{$factor->usrId}|totp"]);
        } elseif ($factor instanceof Mfa\WebAuthnFactor) {
            $revoked = new Mfa\WebAuthnFactor(
                id: $factor->id, usrId: $factor->usrId, identifier: $factor->identifier,
                status: Mfa\FactorStatus::Revoked, replaces: $factor->replaces,
                rpId: $factor->rpId, signCount: $factor->signCount,
                createdAt: $factor->createdAt, updatedAt: $now,
            );
            unset($this->mfaWebauthnByCredentialId[$factor->identifier]);
        } else {
            $revoked = new Mfa\RecoveryFactor(
                id: $factor->id, usrId: $factor->usrId,
                status: Mfa\FactorStatus::Revoked, replaces: $factor->replaces,
                createdAt: $factor->createdAt, updatedAt: $now,
                remaining: $factor->remaining,
            );
            unset($this->mfaActiveSingleton["{$factor->usrId}|recovery"]);
        }
        $this->mfaFactors[$mfaId] = $revoked;
        return $revoked;
    }

    public function verifyMfa(string $usrId, Mfa\MfaProof $proof): Mfa\MfaVerifyResult
    {
        if ($proof instanceof Mfa\TotpProof) return $this->verifyTotp($usrId, $proof->code);
        if ($proof instanceof Mfa\WebAuthnProof) return $this->verifyWebAuthnProof($usrId, $proof);
        if ($proof instanceof Mfa\RecoveryProof) return $this->verifyRecovery($usrId, $proof->code);
        throw new \InvalidArgumentException('Unknown MFA proof type');
    }

    private function verifyTotp(string $usrId, string $code): Mfa\MfaVerifyResult
    {
        $mfaId = $this->mfaActiveSingleton["{$usrId}|totp"] ?? null;
        if ($mfaId === null) {
            throw new Exceptions\InvalidCredentialException('No active TOTP factor for user');
        }
        $secret = $this->mfaTotpSecrets[$mfaId];
        if (!Mfa\Totp::verify($secret, $code, $this->now()->getTimestamp())) {
            throw new Exceptions\InvalidCredentialException('TOTP code did not verify');
        }
        return new Mfa\MfaVerifyResult(
            mfaId: $mfaId, type: Mfa\FactorType::Totp,
            mfaVerifiedAt: $this->now(), newSignCount: null,
        );
    }

    private function verifyWebAuthnProof(string $usrId, Mfa\WebAuthnProof $proof): Mfa\MfaVerifyResult
    {
        $mfaId = $this->mfaWebauthnByCredentialId[$proof->credentialId] ?? null;
        if ($mfaId === null) {
            throw new Exceptions\InvalidCredentialException('No WebAuthn factor for credential id');
        }
        $factor = $this->mfaFactors[$mfaId];
        if (!$factor instanceof Mfa\WebAuthnFactor) {
            throw new Exceptions\InvalidCredentialException('Factor is not WebAuthn');
        }
        if ($factor->usrId !== $usrId) {
            throw new Exceptions\InvalidCredentialException('WebAuthn factor does not belong to user');
        }
        if ($factor->status !== Mfa\FactorStatus::Active) {
            throw new Exceptions\InvalidCredentialException(
                "WebAuthn factor is {$factor->status->value}, not active"
            );
        }
        $result = Mfa\WebAuthn::verifyAssertion(
            cosePublicKey: $this->mfaWebauthnKeys[$mfaId],
            storedSignCount: $factor->signCount,
            storedRpId: $factor->rpId,
            expectedChallenge: $proof->expectedChallenge,
            expectedOrigin: $proof->expectedOrigin,
            authenticatorData: $proof->authenticatorData,
            clientDataJson: $proof->clientDataJson,
            signature: $proof->signature,
        );
        $now = $this->now();
        $this->mfaFactors[$mfaId] = new Mfa\WebAuthnFactor(
            id: $factor->id, usrId: $factor->usrId, identifier: $factor->identifier,
            status: $factor->status, replaces: $factor->replaces,
            rpId: $factor->rpId, signCount: $result->newSignCount,
            createdAt: $factor->createdAt, updatedAt: $now,
        );
        return new Mfa\MfaVerifyResult(
            mfaId: $mfaId, type: Mfa\FactorType::WebAuthn,
            mfaVerifiedAt: $now, newSignCount: $result->newSignCount,
        );
    }

    private function verifyRecovery(string $usrId, string $code): Mfa\MfaVerifyResult
    {
        $mfaId = $this->mfaActiveSingleton["{$usrId}|recovery"] ?? null;
        if ($mfaId === null) {
            throw new Exceptions\InvalidCredentialException('No active recovery factor for user');
        }
        $normalized = Mfa\RecoveryCodes::normalizeInput($code);
        if (!Mfa\RecoveryCodes::isValid($normalized)) {
            throw new Exceptions\InvalidCredentialException('Recovery code is malformed');
        }
        $hashes = $this->mfaRecoveryHashes[$mfaId];
        $consumed =& $this->mfaRecoveryConsumed[$mfaId];
        // Walk every active slot regardless of an early match — keeps work
        // constant relative to the active set so timing doesn't leak which
        // slot matched.
        $matchedSlot = -1;
        foreach ($hashes as $i => $h) {
            if ($consumed[$i]) continue;
            if (PasswordHashing::verify($h, $normalized) && $matchedSlot === -1) {
                $matchedSlot = $i;
            }
        }
        if ($matchedSlot === -1) {
            throw new Exceptions\InvalidCredentialException('Recovery code did not verify');
        }
        $consumed[$matchedSlot] = true;
        $factor = $this->mfaFactors[$mfaId];
        if ($factor instanceof Mfa\RecoveryFactor) {
            $remaining = count(array_filter($consumed, fn($c) => !$c));
            $this->mfaFactors[$mfaId] = new Mfa\RecoveryFactor(
                id: $factor->id, usrId: $factor->usrId,
                status: $factor->status, replaces: $factor->replaces,
                createdAt: $factor->createdAt, updatedAt: $this->now(),
                remaining: $remaining,
            );
        }
        return new Mfa\MfaVerifyResult(
            mfaId: $mfaId, type: Mfa\FactorType::Recovery,
            mfaVerifiedAt: $this->now(), newSignCount: null,
        );
    }

    public function getMfaPolicy(string $usrId): ?Mfa\UserMfaPolicy
    {
        $this->requireUser($usrId);
        return $this->mfaPolicies[$usrId] ?? null;
    }

    public function setMfaPolicy(
        string $usrId,
        bool $required,
        ?\DateTimeImmutable $graceUntil = null,
    ): Mfa\UserMfaPolicy {
        $this->requireUser($usrId);
        $policy = new Mfa\UserMfaPolicy(
            usrId: $usrId,
            required: $required,
            graceUntil: $graceUntil,
            updatedAt: $this->now(),
        );
        $this->mfaPolicies[$usrId] = $policy;
        return $policy;
    }

    // ─── private helpers ───

    private function requireFactor(string $mfaId): Mfa\TotpFactor|Mfa\WebAuthnFactor|Mfa\RecoveryFactor
    {
        $f = $this->mfaFactors[$mfaId] ?? null;
        if ($f === null) {
            throw new Exceptions\NotFoundException("MFA factor {$mfaId} not found");
        }
        return $f;
    }

    private function checkUserActive(string $usrId): void
    {
        $user = $this->requireUser($usrId);
        if ($user->status !== Status::Active) {
            throw new Exceptions\PreconditionException(
                "User {$usrId} is {$user->status->value}; cannot enroll MFA",
                'user_not_active',
            );
        }
    }

    private function enforceNoActiveSingleton(string $usrId, string $type): void
    {
        if (isset($this->mfaActiveSingleton["{$usrId}|{$type}"])) {
            throw new Exceptions\PreconditionException(
                "User {$usrId} already has an active {$type} factor; revoke before re-enrolling",
                'active_singleton_exists',
            );
        }
    }

    private function checkPendingNotExpired(
        Mfa\TotpFactor|Mfa\WebAuthnFactor $factor,
    ): void {
        if ($factor->status !== Mfa\FactorStatus::Pending) return;
        $ageSec = $this->now()->getTimestamp() - $factor->createdAt->getTimestamp();
        if ($ageSec > self::PENDING_FACTOR_TTL_SECONDS) {
            throw new Exceptions\PreconditionException(
                "Pending factor {$factor->id} expired "
                . "({$ageSec}s > " . self::PENDING_FACTOR_TTL_SECONDS . 's)',
                'pending_factor_expired',
            );
        }
    }

    /** Inline RFC 4648 base32 — matches the Python SDK's otpauth URI. */
    private static function base32Encode(string $buf): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = 0; $value = 0; $out = '';
        for ($i = 0, $n = strlen($buf); $i < $n; $i++) {
            $value = ($value << 8) | ord($buf[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $out .= $alphabet[($value >> ($bits - 5)) & 0x1F];
                $bits -= 5;
            }
        }
        if ($bits > 0) {
            $out .= $alphabet[($value << (5 - $bits)) & 0x1F];
        }
        return $out;
    }
}
