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
use Flametrench\Identity\Mfa\FactorStatus;
use Flametrench\Identity\Mfa\FactorType;
use Flametrench\Identity\Mfa\MfaProof;
use Flametrench\Identity\Mfa\MfaVerifyResult;
use Flametrench\Identity\Mfa\RecoveryCodes;
use Flametrench\Identity\Mfa\RecoveryFactor;
use Flametrench\Identity\Mfa\RecoveryProof;
use Flametrench\Identity\Mfa\Totp;
use Flametrench\Identity\Mfa\TotpFactor;
use Flametrench\Identity\Mfa\TotpProof;
use Flametrench\Identity\Mfa\UserMfaPolicy;
use Flametrench\Identity\Mfa\WebAuthn;
use Flametrench\Identity\Mfa\WebAuthnFactor;
use Flametrench\Identity\Mfa\WebAuthnProof;
use Flametrench\Ids\Id;
use PDO;
use PDOException;

/**
 * Postgres-backed IdentityStore. Mirrors InMemoryIdentityStore byte-for-byte
 * at the SDK boundary; the difference is durability and concurrency.
 * Schema lives in spec/reference/postgres.sql.
 *
 * Bearer tokens are SHA-256 hashed and stored as 32 raw bytes (BYTEA).
 * Plaintext tokens are returned ONCE on create/refresh and never persisted.
 *
 * Multi-statement ops (revokeUser cascade, rotation, refreshSession,
 * MFA confirm/verify) run inside a transaction so state transitions are
 * atomic.
 */
final class PostgresIdentityStore implements IdentityStore
{
    /** Pending TOTP/WebAuthn factor TTL per ADR 0008. */
    public const PENDING_FACTOR_TTL_SECONDS = 600;

    private const CRED_COLS =
        'id, usr_id, type, identifier, status, replaces, password_hash, '
        . 'passkey_public_key, passkey_sign_count, passkey_rp_id, '
        . 'oidc_issuer, oidc_subject, created_at, updated_at';

    private const SES_COLS =
        'id, usr_id, cred_id, created_at, expires_at, revoked_at, token_hash, mfa_verified_at';

    private const MFA_COLS =
        'id, usr_id, type, status, replaces, identifier, '
        . 'totp_secret, totp_algorithm, totp_digits, totp_period, '
        . 'webauthn_public_key, webauthn_sign_count, webauthn_rp_id, '
        . 'webauthn_aaguid, webauthn_transports, '
        . 'recovery_hashes, recovery_consumed, pending_expires_at, '
        . 'created_at, updated_at';

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    public function __construct(
        private readonly PDO $pdo,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn(): \DateTimeImmutable => new \DateTimeImmutable();
    }

    private function now(): \DateTimeImmutable
    {
        return ($this->clock)();
    }

    private static function fmt(\DateTimeImmutable $dt): string
    {
        return $dt->format('Y-m-d H:i:s.uP');
    }

    private static function wireToUuid(string $wireId): string
    {
        return Id::decode($wireId)['uuid'];
    }

    /**
     * @template T
     * @param callable(): T $fn
     * @return T
     */
    private function tx(callable $fn): mixed
    {
        $this->pdo->beginTransaction();
        try {
            $result = $fn();
            $this->pdo->commit();
            return $result;
        } catch (\Throwable $e) {
            try {
                $this->pdo->rollBack();
            } catch (\Throwable) {
                // surface original
            }
            throw $e;
        }
    }

    private static function isUniqueViolation(PDOException $e): bool
    {
        $sqlstate = $e->errorInfo[0] ?? null;
        return $sqlstate === '23505' || str_contains($e->getMessage(), 'SQLSTATE[23505]');
    }

    // ─── Row → entity mappers ───

    /** @param array<string, mixed> $r */
    private static function rowToUser(array $r): User
    {
        return new User(
            id: Id::encode('usr', (string) $r['id']),
            status: Status::from((string) $r['status']),
            createdAt: new \DateTimeImmutable((string) $r['created_at']),
            updatedAt: new \DateTimeImmutable((string) $r['updated_at']),
        );
    }

    /** @param array<string, mixed> $r */
    private static function rowToCred(array $r): Credential
    {
        $id = Id::encode('cred', (string) $r['id']);
        $usrId = Id::encode('usr', (string) $r['usr_id']);
        $replaces = $r['replaces'] !== null ? Id::encode('cred', (string) $r['replaces']) : null;
        $createdAt = new \DateTimeImmutable((string) $r['created_at']);
        $updatedAt = new \DateTimeImmutable((string) $r['updated_at']);
        $status = Status::from((string) $r['status']);
        $type = (string) $r['type'];
        $identifier = (string) $r['identifier'];
        if ($type === 'password') {
            return new PasswordCredential(
                id: $id,
                usrId: $usrId,
                identifier: $identifier,
                status: $status,
                replaces: $replaces,
                createdAt: $createdAt,
                updatedAt: $updatedAt,
            );
        }
        if ($type === 'passkey') {
            return new PasskeyCredential(
                id: $id,
                usrId: $usrId,
                identifier: $identifier,
                status: $status,
                replaces: $replaces,
                signCount: (int) $r['passkey_sign_count'],
                rpId: (string) $r['passkey_rp_id'],
                createdAt: $createdAt,
                updatedAt: $updatedAt,
            );
        }
        return new OidcCredential(
            id: $id,
            usrId: $usrId,
            identifier: $identifier,
            status: $status,
            replaces: $replaces,
            oidcIssuer: (string) $r['oidc_issuer'],
            oidcSubject: (string) $r['oidc_subject'],
            createdAt: $createdAt,
            updatedAt: $updatedAt,
        );
    }

    /** @param array<string, mixed> $r */
    private static function rowToSession(array $r): Session
    {
        return new Session(
            id: Id::encode('ses', (string) $r['id']),
            usrId: Id::encode('usr', (string) $r['usr_id']),
            credId: Id::encode('cred', (string) $r['cred_id']),
            createdAt: new \DateTimeImmutable((string) $r['created_at']),
            expiresAt: new \DateTimeImmutable((string) $r['expires_at']),
            revokedAt: $r['revoked_at'] !== null
                ? new \DateTimeImmutable((string) $r['revoked_at'])
                : null,
        );
    }

    /** @param array<string, mixed> $r */
    private static function rowToFactor(array $r): TotpFactor|WebAuthnFactor|RecoveryFactor
    {
        $id = Id::encode('mfa', (string) $r['id']);
        $usrId = Id::encode('usr', (string) $r['usr_id']);
        $replaces = $r['replaces'] !== null ? Id::encode('mfa', (string) $r['replaces']) : null;
        $createdAt = new \DateTimeImmutable((string) $r['created_at']);
        $updatedAt = new \DateTimeImmutable((string) $r['updated_at']);
        $status = FactorStatus::from((string) $r['status']);
        $type = (string) $r['type'];
        if ($type === 'totp') {
            return new TotpFactor(
                id: $id,
                usrId: $usrId,
                identifier: (string) $r['identifier'],
                status: $status,
                replaces: $replaces,
                createdAt: $createdAt,
                updatedAt: $updatedAt,
            );
        }
        if ($type === 'webauthn') {
            return new WebAuthnFactor(
                id: $id,
                usrId: $usrId,
                identifier: (string) $r['identifier'],
                status: $status,
                replaces: $replaces,
                rpId: (string) $r['webauthn_rp_id'],
                signCount: (int) $r['webauthn_sign_count'],
                createdAt: $createdAt,
                updatedAt: $updatedAt,
            );
        }
        $consumed = self::parsePgBoolArray($r['recovery_consumed']);
        $remaining = count(array_filter($consumed, static fn(bool $c) => !$c));
        return new RecoveryFactor(
            id: $id,
            usrId: $usrId,
            status: $status,
            replaces: $replaces,
            createdAt: $createdAt,
            updatedAt: $updatedAt,
            remaining: $remaining,
        );
    }

    /** @param array<string, mixed> $r */
    private static function rowToPolicy(array $r): UserMfaPolicy
    {
        return new UserMfaPolicy(
            usrId: Id::encode('usr', (string) $r['usr_id']),
            required: self::pgBool($r['required']),
            graceUntil: $r['grace_until'] !== null
                ? new \DateTimeImmutable((string) $r['grace_until'])
                : null,
            updatedAt: new \DateTimeImmutable((string) $r['updated_at']),
        );
    }

    private static function pgBool(mixed $v): bool
    {
        if (is_bool($v)) return $v;
        if (is_string($v)) return $v === 't' || $v === 'true' || $v === '1';
        return (bool) $v;
    }

    /**
     * Parse a Postgres `boolean[]` literal as returned by PDO_pgsql.
     * Format: `{t,f,t}` etc.
     *
     * @return list<bool>
     */
    private static function parsePgBoolArray(mixed $raw): array
    {
        if (is_array($raw)) {
            return array_map(self::pgBool(...), array_values($raw));
        }
        if (!is_string($raw) || $raw === '' || $raw === '{}') return [];
        $inner = trim($raw, '{}');
        if ($inner === '') return [];
        return array_map(self::pgBool(...), explode(',', $inner));
    }

    /**
     * Parse a Postgres `text[]` literal as returned by PDO_pgsql.
     * Format: `{a,b,"c, with comma"}` etc.
     *
     * @return list<string>
     */
    private static function parsePgTextArray(mixed $raw): array
    {
        if (is_array($raw)) return array_values(array_map(static fn($x) => (string) $x, $raw));
        if (!is_string($raw) || $raw === '' || $raw === '{}') return [];
        $inner = trim($raw, '{}');
        if ($inner === '') return [];
        // Simple parser: handles unquoted and double-quoted elements,
        // including embedded commas in quoted form. Recovery hashes are
        // PHC-encoded so contain `$` and `,`-free segments only — but
        // we still want quote-aware parsing for safety.
        $out = [];
        $buf = '';
        $inQuote = false;
        $i = 0;
        $len = strlen($inner);
        while ($i < $len) {
            $ch = $inner[$i];
            if ($inQuote) {
                if ($ch === '\\' && $i + 1 < $len) {
                    $buf .= $inner[$i + 1];
                    $i += 2;
                    continue;
                }
                if ($ch === '"') {
                    $inQuote = false;
                    $i++;
                    continue;
                }
                $buf .= $ch;
                $i++;
                continue;
            }
            if ($ch === '"') {
                $inQuote = true;
                $i++;
                continue;
            }
            if ($ch === ',') {
                $out[] = $buf;
                $buf = '';
                $i++;
                continue;
            }
            $buf .= $ch;
            $i++;
        }
        $out[] = $buf;
        return $out;
    }

    /**
     * Encode a list of strings as a Postgres `text[]` literal.
     * @param list<string> $items
     */
    private static function encodePgTextArray(array $items): string
    {
        $parts = array_map(static function (string $s): string {
            $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'], $s);
            return '"' . $escaped . '"';
        }, $items);
        return '{' . implode(',', $parts) . '}';
    }

    /**
     * @param list<bool> $items
     */
    private static function encodePgBoolArray(array $items): string
    {
        return '{' . implode(',', array_map(static fn(bool $b) => $b ? 't' : 'f', $items)) . '}';
    }

    private static function hashTokenBytes(string $token): string
    {
        return hash('sha256', $token, true);
    }

    private static function generateToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    // ─── Users ───

    public function createUser(): User
    {
        $id = Id::decode(Id::generate('usr'))['uuid'];
        $stmt = $this->pdo->prepare(
            'INSERT INTO usr (id) VALUES (?)
             RETURNING id, status, created_at, updated_at'
        );
        $stmt->execute([$id]);
        /** @var array<string, mixed> $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return self::rowToUser($row);
    }

    public function getUser(string $usrId): User
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, status, created_at, updated_at FROM usr WHERE id = ?'
        );
        $stmt->execute([self::wireToUuid($usrId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("User {$usrId} not found");
        }
        return self::rowToUser($row);
    }

    public function suspendUser(string $usrId): User
    {
        return $this->tx(function () use ($usrId) {
            $uuid = self::wireToUuid($usrId);
            $cur = $this->pdo->prepare(
                'SELECT id, status, created_at, updated_at FROM usr WHERE id = ? FOR UPDATE'
            );
            $cur->execute([$uuid]);
            $row = $cur->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("User {$usrId} not found");
            }
            if ($row['status'] === 'revoked') {
                throw new AlreadyTerminalException("User {$usrId} is revoked");
            }
            if ($row['status'] === 'suspended') {
                return self::rowToUser($row);
            }
            $upd = $this->pdo->prepare(
                "UPDATE usr SET status = 'suspended' WHERE id = ?
                 RETURNING id, status, created_at, updated_at"
            );
            $upd->execute([$uuid]);
            /** @var array<string, mixed> $updated */
            $updated = $upd->fetch(PDO::FETCH_ASSOC);
            $rev = $this->pdo->prepare(
                'UPDATE ses SET revoked_at = ?
                 WHERE usr_id = ? AND revoked_at IS NULL'
            );
            $rev->execute([self::fmt($this->now()), $uuid]);
            return self::rowToUser($updated);
        });
    }

    public function reinstateUser(string $usrId): User
    {
        return $this->tx(function () use ($usrId) {
            $uuid = self::wireToUuid($usrId);
            $cur = $this->pdo->prepare(
                'SELECT id, status, created_at, updated_at FROM usr WHERE id = ? FOR UPDATE'
            );
            $cur->execute([$uuid]);
            $row = $cur->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("User {$usrId} not found");
            }
            if ($row['status'] !== 'suspended') {
                throw new PreconditionException(
                    "User {$usrId} is {$row['status']}; only suspended users can be reinstated",
                    'invalid_transition',
                );
            }
            $upd = $this->pdo->prepare(
                "UPDATE usr SET status = 'active' WHERE id = ?
                 RETURNING id, status, created_at, updated_at"
            );
            $upd->execute([$uuid]);
            /** @var array<string, mixed> $updated */
            $updated = $upd->fetch(PDO::FETCH_ASSOC);
            return self::rowToUser($updated);
        });
    }

    public function revokeUser(string $usrId): User
    {
        return $this->tx(function () use ($usrId) {
            $uuid = self::wireToUuid($usrId);
            $cur = $this->pdo->prepare(
                'SELECT id, status, created_at, updated_at FROM usr WHERE id = ? FOR UPDATE'
            );
            $cur->execute([$uuid]);
            $row = $cur->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("User {$usrId} not found");
            }
            if ($row['status'] === 'revoked') {
                throw new AlreadyTerminalException("User {$usrId} is already revoked");
            }
            $now = self::fmt($this->now());
            $stmt = $this->pdo->prepare(
                "UPDATE cred SET status = 'revoked'
                 WHERE usr_id = ? AND status = 'active'"
            );
            $stmt->execute([$uuid]);
            $stmt = $this->pdo->prepare(
                'UPDATE ses SET revoked_at = ?
                 WHERE usr_id = ? AND revoked_at IS NULL'
            );
            $stmt->execute([$now, $uuid]);
            $upd = $this->pdo->prepare(
                "UPDATE usr SET status = 'revoked' WHERE id = ?
                 RETURNING id, status, created_at, updated_at"
            );
            $upd->execute([$uuid]);
            /** @var array<string, mixed> $updated */
            $updated = $upd->fetch(PDO::FETCH_ASSOC);
            return self::rowToUser($updated);
        });
    }

    // ─── Credentials ───

    private function ensureUserActive(string $usrId): string
    {
        $userUuid = self::wireToUuid($usrId);
        $stmt = $this->pdo->prepare('SELECT status FROM usr WHERE id = ?');
        $stmt->execute([$userUuid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("User {$usrId} not found");
        }
        if ($row['status'] !== 'active') {
            throw new PreconditionException(
                "Cannot create credentials for {$row['status']} user",
                'user_not_active',
            );
        }
        return $userUuid;
    }

    public function createPasswordCredential(
        string $usrId,
        string $identifier,
        string $password,
    ): PasswordCredential {
        $userUuid = $this->ensureUserActive($usrId);
        $id = Id::decode(Id::generate('cred'))['uuid'];
        $hash = PasswordHashing::hash($password);
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO cred (id, usr_id, type, identifier, password_hash)
                 VALUES (?, ?, 'password', ?, ?)
                 RETURNING " . self::CRED_COLS
            );
            $stmt->execute([$id, $userUuid, $identifier, $hash]);
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $cred = self::rowToCred($row);
            assert($cred instanceof PasswordCredential);
            return $cred;
        } catch (PDOException $e) {
            if (self::isUniqueViolation($e)) {
                throw new DuplicateCredentialException(
                    "An active password credential already exists for identifier {$identifier}",
                );
            }
            throw $e;
        }
    }

    public function createPasskeyCredential(
        string $usrId,
        string $identifier,
        string $publicKey,
        int $signCount,
        string $rpId,
    ): PasskeyCredential {
        $userUuid = $this->ensureUserActive($usrId);
        $id = Id::decode(Id::generate('cred'))['uuid'];
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO cred (id, usr_id, type, identifier,
                                   passkey_public_key, passkey_sign_count, passkey_rp_id)
                 VALUES (?, ?, 'passkey', ?, ?, ?, ?)
                 RETURNING " . self::CRED_COLS
            );
            $stmt->bindValue(1, $id);
            $stmt->bindValue(2, $userUuid);
            $stmt->bindValue(3, $identifier);
            $stmt->bindValue(4, $publicKey, PDO::PARAM_LOB);
            $stmt->bindValue(5, $signCount);
            $stmt->bindValue(6, $rpId);
            $stmt->execute();
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $cred = self::rowToCred($row);
            assert($cred instanceof PasskeyCredential);
            return $cred;
        } catch (PDOException $e) {
            if (self::isUniqueViolation($e)) {
                throw new DuplicateCredentialException(
                    "An active passkey credential already exists for identifier {$identifier}",
                );
            }
            throw $e;
        }
    }

    public function createOidcCredential(
        string $usrId,
        string $identifier,
        string $oidcIssuer,
        string $oidcSubject,
    ): OidcCredential {
        $userUuid = $this->ensureUserActive($usrId);
        $id = Id::decode(Id::generate('cred'))['uuid'];
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO cred (id, usr_id, type, identifier, oidc_issuer, oidc_subject)
                 VALUES (?, ?, 'oidc', ?, ?, ?)
                 RETURNING " . self::CRED_COLS
            );
            $stmt->execute([$id, $userUuid, $identifier, $oidcIssuer, $oidcSubject]);
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $cred = self::rowToCred($row);
            assert($cred instanceof OidcCredential);
            return $cred;
        } catch (PDOException $e) {
            if (self::isUniqueViolation($e)) {
                throw new DuplicateCredentialException(
                    "An active oidc credential already exists for identifier {$identifier}",
                );
            }
            throw $e;
        }
    }

    public function getCredential(string $credId): Credential
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::CRED_COLS . ' FROM cred WHERE id = ?'
        );
        $stmt->execute([self::wireToUuid($credId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("Credential {$credId} not found");
        }
        return self::rowToCred($row);
    }

    public function listCredentialsForUser(string $usrId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::CRED_COLS . ' FROM cred WHERE usr_id = ? ORDER BY created_at'
        );
        $stmt->execute([self::wireToUuid($usrId)]);
        return array_map(self::rowToCred(...), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function findCredentialByIdentifier(
        CredentialType $type,
        string $identifier,
    ): ?Credential {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::CRED_COLS . " FROM cred
             WHERE type = ? AND identifier = ? AND status = 'active'"
        );
        $stmt->execute([$type->value, $identifier]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) return null;
        return self::rowToCred($row);
    }

    /**
     * @return array<string, mixed> Locked old cred row.
     */
    private function lockCredForRotation(string $credId, CredentialType $expected): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::CRED_COLS . ' FROM cred WHERE id = ? FOR UPDATE'
        );
        $stmt->execute([self::wireToUuid($credId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("Credential {$credId} not found");
        }
        if ($row['status'] !== 'active') {
            throw new CredentialNotActiveException("Credential {$credId} is {$row['status']}");
        }
        if ($row['type'] !== $expected->value) {
            throw new CredentialTypeMismatchException(
                "Cannot rotate {$row['type']} credential with {$expected->value} payload",
            );
        }
        return $row;
    }

    private function revokeOldOnRotation(array $old, string $now): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE cred SET status = 'revoked' WHERE id = ?"
        );
        $stmt->execute([$old['id']]);
        $stmt = $this->pdo->prepare(
            'UPDATE ses SET revoked_at = ?
             WHERE cred_id = ? AND revoked_at IS NULL'
        );
        $stmt->execute([$now, $old['id']]);
    }

    public function rotatePassword(string $credId, string $newPassword): PasswordCredential
    {
        return $this->tx(function () use ($credId, $newPassword) {
            $old = $this->lockCredForRotation($credId, CredentialType::Password);
            $now = self::fmt($this->now());
            $this->revokeOldOnRotation($old, $now);
            $newId = Id::decode(Id::generate('cred'))['uuid'];
            $hash = PasswordHashing::hash($newPassword);
            $stmt = $this->pdo->prepare(
                "INSERT INTO cred (id, usr_id, type, identifier, password_hash, replaces)
                 VALUES (?, ?, 'password', ?, ?, ?)
                 RETURNING " . self::CRED_COLS
            );
            $stmt->execute([$newId, $old['usr_id'], $old['identifier'], $hash, $old['id']]);
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $cred = self::rowToCred($row);
            assert($cred instanceof PasswordCredential);
            return $cred;
        });
    }

    public function rotatePasskey(
        string $credId,
        string $publicKey,
        int $signCount,
        string $rpId,
    ): PasskeyCredential {
        return $this->tx(function () use ($credId, $publicKey, $signCount, $rpId) {
            $old = $this->lockCredForRotation($credId, CredentialType::Passkey);
            $now = self::fmt($this->now());
            $this->revokeOldOnRotation($old, $now);
            $newId = Id::decode(Id::generate('cred'))['uuid'];
            $stmt = $this->pdo->prepare(
                "INSERT INTO cred (id, usr_id, type, identifier,
                                   passkey_public_key, passkey_sign_count, passkey_rp_id, replaces)
                 VALUES (?, ?, 'passkey', ?, ?, ?, ?, ?)
                 RETURNING " . self::CRED_COLS
            );
            $stmt->bindValue(1, $newId);
            $stmt->bindValue(2, $old['usr_id']);
            $stmt->bindValue(3, $old['identifier']);
            $stmt->bindValue(4, $publicKey, PDO::PARAM_LOB);
            $stmt->bindValue(5, $signCount);
            $stmt->bindValue(6, $rpId);
            $stmt->bindValue(7, $old['id']);
            $stmt->execute();
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $cred = self::rowToCred($row);
            assert($cred instanceof PasskeyCredential);
            return $cred;
        });
    }

    public function rotateOidc(
        string $credId,
        string $oidcIssuer,
        string $oidcSubject,
    ): OidcCredential {
        return $this->tx(function () use ($credId, $oidcIssuer, $oidcSubject) {
            $old = $this->lockCredForRotation($credId, CredentialType::Oidc);
            $now = self::fmt($this->now());
            $this->revokeOldOnRotation($old, $now);
            $newId = Id::decode(Id::generate('cred'))['uuid'];
            $stmt = $this->pdo->prepare(
                "INSERT INTO cred (id, usr_id, type, identifier, oidc_issuer, oidc_subject, replaces)
                 VALUES (?, ?, 'oidc', ?, ?, ?, ?)
                 RETURNING " . self::CRED_COLS
            );
            $stmt->execute([
                $newId, $old['usr_id'], $old['identifier'],
                $oidcIssuer, $oidcSubject, $old['id'],
            ]);
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $cred = self::rowToCred($row);
            assert($cred instanceof OidcCredential);
            return $cred;
        });
    }

    public function suspendCredential(string $credId): Credential
    {
        return $this->tx(function () use ($credId) {
            $uuid = self::wireToUuid($credId);
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::CRED_COLS . ' FROM cred WHERE id = ? FOR UPDATE'
            );
            $stmt->execute([$uuid]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("Credential {$credId} not found");
            }
            if ($row['status'] !== 'active') {
                throw new PreconditionException(
                    "Credential {$credId} is {$row['status']}; only active credentials can be suspended",
                    'cred_not_active',
                );
            }
            $now = self::fmt($this->now());
            $upd = $this->pdo->prepare(
                "UPDATE cred SET status = 'suspended' WHERE id = ?
                 RETURNING " . self::CRED_COLS
            );
            $upd->execute([$uuid]);
            /** @var array<string, mixed> $updated */
            $updated = $upd->fetch(PDO::FETCH_ASSOC);
            $rev = $this->pdo->prepare(
                'UPDATE ses SET revoked_at = ?
                 WHERE cred_id = ? AND revoked_at IS NULL'
            );
            $rev->execute([$now, $uuid]);
            return self::rowToCred($updated);
        });
    }

    public function reinstateCredential(string $credId): Credential
    {
        return $this->tx(function () use ($credId) {
            $uuid = self::wireToUuid($credId);
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::CRED_COLS . ' FROM cred WHERE id = ? FOR UPDATE'
            );
            $stmt->execute([$uuid]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("Credential {$credId} not found");
            }
            if ($row['status'] !== 'suspended') {
                throw new PreconditionException(
                    "Credential {$credId} is {$row['status']}; only suspended credentials can be reinstated",
                    'invalid_transition',
                );
            }
            try {
                $upd = $this->pdo->prepare(
                    "UPDATE cred SET status = 'active' WHERE id = ?
                     RETURNING " . self::CRED_COLS
                );
                $upd->execute([$uuid]);
                /** @var array<string, mixed> $updated */
                $updated = $upd->fetch(PDO::FETCH_ASSOC);
                return self::rowToCred($updated);
            } catch (PDOException $e) {
                if (self::isUniqueViolation($e)) {
                    throw new DuplicateCredentialException(
                        "Another active {$row['type']} credential already exists for {$row['identifier']}; cannot reinstate",
                    );
                }
                throw $e;
            }
        });
    }

    public function revokeCredential(string $credId): Credential
    {
        return $this->tx(function () use ($credId) {
            $uuid = self::wireToUuid($credId);
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::CRED_COLS . ' FROM cred WHERE id = ? FOR UPDATE'
            );
            $stmt->execute([$uuid]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("Credential {$credId} not found");
            }
            if ($row['status'] === 'revoked') {
                throw new AlreadyTerminalException("Credential {$credId} is already revoked");
            }
            $now = self::fmt($this->now());
            $upd = $this->pdo->prepare(
                "UPDATE cred SET status = 'revoked' WHERE id = ?
                 RETURNING " . self::CRED_COLS
            );
            $upd->execute([$uuid]);
            /** @var array<string, mixed> $updated */
            $updated = $upd->fetch(PDO::FETCH_ASSOC);
            $rev = $this->pdo->prepare(
                'UPDATE ses SET revoked_at = ?
                 WHERE cred_id = ? AND revoked_at IS NULL'
            );
            $rev->execute([$now, $uuid]);
            return self::rowToCred($updated);
        });
    }

    public function verifyPassword(string $identifier, string $password): VerifiedCredential
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::CRED_COLS . " FROM cred
             WHERE type = 'password' AND identifier = ? AND status = 'active'"
        );
        $stmt->execute([$identifier]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false || $row['password_hash'] === null) {
            throw new InvalidCredentialException('Invalid credential');
        }
        if (!PasswordHashing::verify((string) $row['password_hash'], $password)) {
            throw new InvalidCredentialException('Invalid credential');
        }
        return new VerifiedCredential(
            usrId: Id::encode('usr', (string) $row['usr_id']),
            credId: Id::encode('cred', (string) $row['id']),
        );
    }

    // ─── Sessions ───

    public function createSession(string $usrId, string $credId, int $ttlSeconds): SessionWithToken
    {
        if ($ttlSeconds < 60) {
            throw new PreconditionException('ttlSeconds must be >= 60', 'ttl_too_short');
        }
        return $this->tx(function () use ($usrId, $credId, $ttlSeconds) {
            $userUuid = self::wireToUuid($usrId);
            $credUuid = self::wireToUuid($credId);
            $stmt = $this->pdo->prepare('SELECT status FROM usr WHERE id = ?');
            $stmt->execute([$userUuid]);
            $userRow = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($userRow === false) {
                throw new NotFoundException("User {$usrId} not found");
            }
            if ($userRow['status'] !== 'active') {
                throw new PreconditionException(
                    "Cannot create session for {$userRow['status']} user",
                    'user_not_active',
                );
            }
            $stmt = $this->pdo->prepare('SELECT status, usr_id FROM cred WHERE id = ?');
            $stmt->execute([$credUuid]);
            $credRow = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($credRow === false) {
                throw new NotFoundException("Credential {$credId} not found");
            }
            if ($credRow['status'] !== 'active') {
                throw new CredentialNotActiveException(
                    "Credential {$credId} is {$credRow['status']}",
                );
            }
            if ($credRow['usr_id'] !== $userUuid) {
                throw new PreconditionException(
                    "Credential {$credId} does not belong to {$usrId}",
                    'cred_user_mismatch',
                );
            }
            $now = $this->now();
            $expiresAt = $now->modify("+{$ttlSeconds} seconds");
            $id = Id::decode(Id::generate('ses'))['uuid'];
            $token = self::generateToken();
            $tokenHash = self::hashTokenBytes($token);
            $stmt = $this->pdo->prepare(
                'INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)
                 VALUES (?, ?, ?, ?, ?, ?)
                 RETURNING ' . self::SES_COLS
            );
            $stmt->bindValue(1, $id);
            $stmt->bindValue(2, $userUuid);
            $stmt->bindValue(3, $credUuid);
            $stmt->bindValue(4, self::fmt($now));
            $stmt->bindValue(5, self::fmt($expiresAt));
            $stmt->bindValue(6, $tokenHash, PDO::PARAM_LOB);
            $stmt->execute();
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            return new SessionWithToken(
                session: self::rowToSession($row),
                token: $token,
            );
        });
    }

    public function getSession(string $sesId): Session
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::SES_COLS . ' FROM ses WHERE id = ?'
        );
        $stmt->execute([self::wireToUuid($sesId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("Session {$sesId} not found");
        }
        return self::rowToSession($row);
    }

    public function listSessionsForUser(string $usrId, ?string $cursor = null, int $limit = 50): Page
    {
        $params = [self::wireToUuid($usrId)];
        $sql = 'SELECT ' . self::SES_COLS . ' FROM ses WHERE usr_id = ?';
        if ($cursor !== null) {
            $sql .= ' AND id > ?';
            $params[] = self::wireToUuid($cursor);
        }
        $params[] = min($limit, 200) + 1;
        $sql .= ' ORDER BY id LIMIT ?';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $page = array_slice($rows, 0, $limit);
        $sessions = array_map(self::rowToSession(...), $page);
        $next = count($rows) > $limit && count($sessions) > 0
            ? $sessions[count($sessions) - 1]->id
            : null;
        return new Page(data: $sessions, nextCursor: $next);
    }

    public function verifySessionToken(string $token): Session
    {
        $tokenHash = self::hashTokenBytes($token);
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::SES_COLS . ' FROM ses WHERE token_hash = ?'
        );
        $stmt->bindValue(1, $tokenHash, PDO::PARAM_LOB);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new InvalidTokenException('Invalid token');
        }
        // Constant-time compare against the stored hash.
        $stored = is_resource($row['token_hash']) ? stream_get_contents($row['token_hash']) : (string) $row['token_hash'];
        if ($stored === false || !hash_equals($tokenHash, $stored)) {
            throw new InvalidTokenException('Invalid token');
        }
        if ($row['revoked_at'] !== null) {
            throw new SessionExpiredException('Session is revoked');
        }
        $expiresAt = new \DateTimeImmutable((string) $row['expires_at']);
        if ($this->now() > $expiresAt) {
            throw new SessionExpiredException('Session has expired');
        }
        $row['token_hash'] = $stored;
        return self::rowToSession($row);
    }

    public function refreshSession(string $sesId): SessionWithToken
    {
        return $this->tx(function () use ($sesId) {
            $uuid = self::wireToUuid($sesId);
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::SES_COLS . ' FROM ses WHERE id = ? FOR UPDATE'
            );
            $stmt->execute([$uuid]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new NotFoundException("Session {$sesId} not found");
            }
            if ($row['revoked_at'] !== null) {
                throw new SessionExpiredException('Session is already revoked');
            }
            $now = $this->now();
            $createdAt = new \DateTimeImmutable((string) $row['created_at']);
            $expiresAt = new \DateTimeImmutable((string) $row['expires_at']);
            if ($now > $expiresAt) {
                throw new SessionExpiredException('Session has expired');
            }
            $stmt = $this->pdo->prepare('UPDATE ses SET revoked_at = ? WHERE id = ?');
            $stmt->execute([self::fmt($now), $uuid]);
            $ttlSec = $expiresAt->getTimestamp() - $createdAt->getTimestamp();
            $newId = Id::decode(Id::generate('ses'))['uuid'];
            $token = self::generateToken();
            $tokenHash = self::hashTokenBytes($token);
            $stmt = $this->pdo->prepare(
                'INSERT INTO ses (id, usr_id, cred_id, created_at, expires_at, token_hash)
                 VALUES (?, ?, ?, ?, ?, ?)
                 RETURNING ' . self::SES_COLS
            );
            $stmt->bindValue(1, $newId);
            $stmt->bindValue(2, $row['usr_id']);
            $stmt->bindValue(3, $row['cred_id']);
            $stmt->bindValue(4, self::fmt($now));
            $stmt->bindValue(5, self::fmt($now->modify("+{$ttlSec} seconds")));
            $stmt->bindValue(6, $tokenHash, PDO::PARAM_LOB);
            $stmt->execute();
            /** @var array<string, mixed> $newRow */
            $newRow = $stmt->fetch(PDO::FETCH_ASSOC);
            return new SessionWithToken(
                session: self::rowToSession($newRow),
                token: $token,
            );
        });
    }

    public function revokeSession(string $sesId): Session
    {
        $uuid = self::wireToUuid($sesId);
        $stmt = $this->pdo->prepare(
            'UPDATE ses SET revoked_at = COALESCE(revoked_at, ?)
             WHERE id = ?
             RETURNING ' . self::SES_COLS
        );
        $stmt->execute([self::fmt($this->now()), $uuid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("Session {$sesId} not found");
        }
        return self::rowToSession($row);
    }

    // ─── MFA ───

    private function requireUserActiveForMfa(string $usrId): string
    {
        $userUuid = self::wireToUuid($usrId);
        $stmt = $this->pdo->prepare('SELECT status FROM usr WHERE id = ?');
        $stmt->execute([$userUuid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("User {$usrId} not found");
        }
        if ($row['status'] !== 'active') {
            throw new PreconditionException(
                "User {$usrId} is {$row['status']}; cannot enroll MFA",
                'user_not_active',
            );
        }
        return $userUuid;
    }

    public function enrollTotpFactor(string $usrId, string $identifier): array
    {
        $userUuid = $this->requireUserActiveForMfa($usrId);
        // The partial-unique index `mfa_unique_active_singleton` only
        // fires on status='active'; new TOTP factors are inserted as
        // 'pending', so the duplicate-active check is explicit.
        $stmt = $this->pdo->prepare(
            "SELECT 1 FROM mfa WHERE usr_id = ? AND type = 'totp' AND status = 'active'"
        );
        $stmt->execute([$userUuid]);
        if ($stmt->fetch(PDO::FETCH_ASSOC) !== false) {
            throw new PreconditionException(
                "User {$usrId} already has an active totp factor; revoke before re-enrolling",
                'active_singleton_exists',
            );
        }
        $now = $this->now();
        $secret = Totp::generateSecret();
        $id = Id::decode(Id::generate('mfa'))['uuid'];
        $expiresAt = $now->modify('+' . self::PENDING_FACTOR_TTL_SECONDS . ' seconds');
        $stmt = $this->pdo->prepare(
            "INSERT INTO mfa (id, usr_id, type, status, identifier,
                              totp_secret, totp_algorithm, totp_digits, totp_period,
                              pending_expires_at, created_at, updated_at)
             VALUES (?, ?, 'totp', 'pending', ?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING " . self::MFA_COLS
        );
        $stmt->bindValue(1, $id);
        $stmt->bindValue(2, $userUuid);
        $stmt->bindValue(3, $identifier);
        $stmt->bindValue(4, $secret, PDO::PARAM_LOB);
        $stmt->bindValue(5, Totp::DEFAULT_ALGORITHM);
        $stmt->bindValue(6, Totp::DEFAULT_DIGITS);
        $stmt->bindValue(7, Totp::DEFAULT_PERIOD);
        $stmt->bindValue(8, self::fmt($expiresAt));
        $stmt->bindValue(9, self::fmt($now));
        $stmt->bindValue(10, self::fmt($now));
        $stmt->execute();
        /** @var array<string, mixed> $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $factor = self::rowToFactor($row);
        assert($factor instanceof TotpFactor);
        return [
            'factor' => $factor,
            'secretB32' => rtrim(self::base32Encode($secret), '='),
            'otpauthUri' => Totp::otpauthUri($secret, $identifier, 'Flametrench'),
        ];
    }

    /** RFC 4648 base32 encoding (with padding). Inlined to mirror InMemoryIdentityStore. */
    private static function base32Encode(string $buf): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = 0;
        $value = 0;
        $out = '';
        $len = strlen($buf);
        for ($i = 0; $i < $len; $i++) {
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
        while (strlen($out) % 8 !== 0) {
            $out .= '=';
        }
        return $out;
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
        $userUuid = $this->requireUserActiveForMfa($usrId);
        $now = $this->now();
        $id = Id::decode(Id::generate('mfa'))['uuid'];
        $expiresAt = $now->modify('+' . self::PENDING_FACTOR_TTL_SECONDS . ' seconds');
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO mfa (id, usr_id, type, status, identifier,
                                  webauthn_public_key, webauthn_sign_count, webauthn_rp_id,
                                  webauthn_aaguid, webauthn_transports,
                                  pending_expires_at, created_at, updated_at)
                 VALUES (?, ?, 'webauthn', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 RETURNING " . self::MFA_COLS
            );
            $stmt->bindValue(1, $id);
            $stmt->bindValue(2, $userUuid);
            $stmt->bindValue(3, $identifier);
            $stmt->bindValue(4, $publicKey, PDO::PARAM_LOB);
            $stmt->bindValue(5, $signCount);
            $stmt->bindValue(6, $rpId);
            $stmt->bindValue(7, $aaguid);
            $stmt->bindValue(8, $transports !== null ? self::encodePgTextArray($transports) : null);
            $stmt->bindValue(9, self::fmt($expiresAt));
            $stmt->bindValue(10, self::fmt($now));
            $stmt->bindValue(11, self::fmt($now));
            $stmt->execute();
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $factor = self::rowToFactor($row);
            assert($factor instanceof WebAuthnFactor);
            return ['factor' => $factor];
        } catch (PDOException $e) {
            if (self::isUniqueViolation($e)) {
                throw new PreconditionException(
                    "WebAuthn credential " . json_encode($identifier) . " is already enrolled",
                    'duplicate_webauthn_credential',
                );
            }
            throw $e;
        }
    }

    public function enrollRecoveryFactor(string $usrId): array
    {
        $userUuid = $this->requireUserActiveForMfa($usrId);
        $now = $this->now();
        $codes = RecoveryCodes::generateSet();
        $hashes = array_map(static fn(string $c) => PasswordHashing::hash($c), $codes);
        $consumed = array_fill(0, count($codes), false);
        $id = Id::decode(Id::generate('mfa'))['uuid'];
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO mfa (id, usr_id, type, status,
                                  recovery_hashes, recovery_consumed,
                                  created_at, updated_at)
                 VALUES (?, ?, 'recovery', 'active', ?, ?, ?, ?)
                 RETURNING " . self::MFA_COLS
            );
            $stmt->execute([
                $id, $userUuid,
                self::encodePgTextArray($hashes),
                self::encodePgBoolArray($consumed),
                self::fmt($now), self::fmt($now),
            ]);
            /** @var array<string, mixed> $row */
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $factor = self::rowToFactor($row);
            assert($factor instanceof RecoveryFactor);
            return ['factor' => $factor, 'codes' => $codes];
        } catch (PDOException $e) {
            if (self::isUniqueViolation($e)) {
                throw new PreconditionException(
                    "User {$usrId} already has an active recovery factor; revoke before re-enrolling",
                    'active_singleton_exists',
                );
            }
            throw $e;
        }
    }

    public function getMfaFactor(string $mfaId): TotpFactor|WebAuthnFactor|RecoveryFactor
    {
        $stmt = $this->pdo->prepare('SELECT ' . self::MFA_COLS . ' FROM mfa WHERE id = ?');
        $stmt->execute([self::wireToUuid($mfaId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("MFA factor {$mfaId} not found");
        }
        return self::rowToFactor($row);
    }

    public function listMfaFactors(string $usrId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::MFA_COLS . ' FROM mfa WHERE usr_id = ? ORDER BY created_at'
        );
        $stmt->execute([self::wireToUuid($usrId)]);
        return array_map(self::rowToFactor(...), $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function confirmTotpFactor(string $mfaId, string $code): TotpFactor
    {
        return $this->tx(function () use ($mfaId, $code) {
            $row = $this->lockMfa($mfaId);
            if ($row['type'] !== 'totp') {
                throw new CredentialTypeMismatchException(
                    "Factor {$mfaId} is {$row['type']}, not totp",
                );
            }
            if ($row['status'] !== 'pending') {
                throw new PreconditionException(
                    "Factor {$mfaId} is {$row['status']}; only pending factors confirm",
                    'factor_not_pending',
                );
            }
            $this->checkPendingNotExpired($row);
            $secret = is_resource($row['totp_secret'])
                ? stream_get_contents($row['totp_secret'])
                : (string) $row['totp_secret'];
            if (!Totp::verify($secret ?: '', $code)) {
                throw new InvalidCredentialException('TOTP code did not verify');
            }
            $stmt = $this->pdo->prepare(
                "UPDATE mfa SET status = 'active', pending_expires_at = NULL WHERE id = ?
                 RETURNING " . self::MFA_COLS
            );
            $stmt->execute([$row['id']]);
            /** @var array<string, mixed> $updated */
            $updated = $stmt->fetch(PDO::FETCH_ASSOC);
            $factor = self::rowToFactor($updated);
            assert($factor instanceof TotpFactor);
            return $factor;
        });
    }

    public function confirmWebAuthnFactor(
        string $mfaId,
        string $authenticatorData,
        string $clientDataJson,
        string $signature,
        string $expectedChallenge,
        string $expectedOrigin,
    ): WebAuthnFactor {
        return $this->tx(function () use (
            $mfaId, $authenticatorData, $clientDataJson, $signature,
            $expectedChallenge, $expectedOrigin,
        ) {
            $row = $this->lockMfa($mfaId);
            if ($row['type'] !== 'webauthn') {
                throw new CredentialTypeMismatchException(
                    "Factor {$mfaId} is {$row['type']}, not webauthn",
                );
            }
            if ($row['status'] !== 'pending') {
                throw new PreconditionException(
                    "Factor {$mfaId} is {$row['status']}; only pending factors confirm",
                    'factor_not_pending',
                );
            }
            $this->checkPendingNotExpired($row);
            $publicKey = is_resource($row['webauthn_public_key'])
                ? stream_get_contents($row['webauthn_public_key'])
                : (string) $row['webauthn_public_key'];
            $result = WebAuthn::verifyAssertion(
                cosePublicKey: $publicKey ?: '',
                storedSignCount: (int) $row['webauthn_sign_count'],
                storedRpId: (string) $row['webauthn_rp_id'],
                expectedChallenge: $expectedChallenge,
                expectedOrigin: $expectedOrigin,
                authenticatorData: $authenticatorData,
                clientDataJson: $clientDataJson,
                signature: $signature,
            );
            $stmt = $this->pdo->prepare(
                "UPDATE mfa SET status = 'active', webauthn_sign_count = ?, pending_expires_at = NULL
                 WHERE id = ?
                 RETURNING " . self::MFA_COLS
            );
            $stmt->execute([$result->newSignCount, $row['id']]);
            /** @var array<string, mixed> $updated */
            $updated = $stmt->fetch(PDO::FETCH_ASSOC);
            $factor = self::rowToFactor($updated);
            assert($factor instanceof WebAuthnFactor);
            return $factor;
        });
    }

    public function revokeMfaFactor(string $mfaId): TotpFactor|WebAuthnFactor|RecoveryFactor
    {
        return $this->tx(function () use ($mfaId) {
            $row = $this->lockMfa($mfaId);
            if ($row['status'] === 'revoked') {
                return self::rowToFactor($row);
            }
            $stmt = $this->pdo->prepare(
                "UPDATE mfa SET status = 'revoked', pending_expires_at = NULL WHERE id = ?
                 RETURNING " . self::MFA_COLS
            );
            $stmt->execute([$row['id']]);
            /** @var array<string, mixed> $updated */
            $updated = $stmt->fetch(PDO::FETCH_ASSOC);
            return self::rowToFactor($updated);
        });
    }

    public function verifyMfa(string $usrId, MfaProof $proof): MfaVerifyResult
    {
        if ($proof instanceof TotpProof) {
            return $this->verifyTotpProof($usrId, $proof->code);
        }
        if ($proof instanceof WebAuthnProof) {
            return $this->verifyWebAuthnProof($usrId, $proof);
        }
        if ($proof instanceof RecoveryProof) {
            return $this->verifyRecoveryProof($usrId, $proof->code);
        }
        throw new InvalidCredentialException('Unsupported MFA proof type');
    }

    private function verifyTotpProof(string $usrId, string $code): MfaVerifyResult
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::MFA_COLS . " FROM mfa
             WHERE usr_id = ? AND type = 'totp' AND status = 'active'"
        );
        $stmt->execute([self::wireToUuid($usrId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new InvalidCredentialException('No active TOTP factor for user');
        }
        $secret = is_resource($row['totp_secret'])
            ? stream_get_contents($row['totp_secret'])
            : (string) $row['totp_secret'];
        if (!Totp::verify($secret ?: '', $code)) {
            throw new InvalidCredentialException('TOTP code did not verify');
        }
        return new MfaVerifyResult(
            mfaId: Id::encode('mfa', (string) $row['id']),
            type: FactorType::Totp,
            mfaVerifiedAt: $this->now(),
        );
    }

    private function verifyWebAuthnProof(string $usrId, WebAuthnProof $proof): MfaVerifyResult
    {
        return $this->tx(function () use ($usrId, $proof) {
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::MFA_COLS . " FROM mfa
                 WHERE identifier = ? AND type = 'webauthn' AND status = 'active'
                 FOR UPDATE"
            );
            $stmt->execute([$proof->credentialId]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new InvalidCredentialException('No WebAuthn factor for credential id');
            }
            $userUuid = self::wireToUuid($usrId);
            if ($row['usr_id'] !== $userUuid) {
                throw new InvalidCredentialException('WebAuthn factor does not belong to user');
            }
            $publicKey = is_resource($row['webauthn_public_key'])
                ? stream_get_contents($row['webauthn_public_key'])
                : (string) $row['webauthn_public_key'];
            $result = WebAuthn::verifyAssertion(
                cosePublicKey: $publicKey ?: '',
                storedSignCount: (int) $row['webauthn_sign_count'],
                storedRpId: (string) $row['webauthn_rp_id'],
                expectedChallenge: $proof->expectedChallenge,
                expectedOrigin: $proof->expectedOrigin,
                authenticatorData: $proof->authenticatorData,
                clientDataJson: $proof->clientDataJson,
                signature: $proof->signature,
            );
            $upd = $this->pdo->prepare(
                'UPDATE mfa SET webauthn_sign_count = ? WHERE id = ?'
            );
            $upd->execute([$result->newSignCount, $row['id']]);
            return new MfaVerifyResult(
                mfaId: Id::encode('mfa', (string) $row['id']),
                type: FactorType::WebAuthn,
                mfaVerifiedAt: $this->now(),
                newSignCount: $result->newSignCount,
            );
        });
    }

    private function verifyRecoveryProof(string $usrId, string $code): MfaVerifyResult
    {
        $normalized = RecoveryCodes::normalizeInput($code);
        if (!RecoveryCodes::isValid($normalized)) {
            throw new InvalidCredentialException('Recovery code is malformed');
        }
        return $this->tx(function () use ($usrId, $normalized) {
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::MFA_COLS . " FROM mfa
                 WHERE usr_id = ? AND type = 'recovery' AND status = 'active'
                 FOR UPDATE"
            );
            $stmt->execute([self::wireToUuid($usrId)]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($row === false) {
                throw new InvalidCredentialException('No active recovery factor for user');
            }
            $hashes = self::parsePgTextArray($row['recovery_hashes']);
            $consumed = self::parsePgBoolArray($row['recovery_consumed']);
            // Walk every active slot regardless of an early match to keep
            // work constant relative to the active set.
            $matched = -1;
            foreach ($hashes as $i => $hash) {
                if ($consumed[$i] ?? false) continue;
                if (PasswordHashing::verify($hash, $normalized) && $matched === -1) {
                    $matched = $i;
                }
            }
            if ($matched === -1) {
                throw new InvalidCredentialException('Recovery code did not verify');
            }
            $consumed[$matched] = true;
            $upd = $this->pdo->prepare(
                'UPDATE mfa SET recovery_consumed = ? WHERE id = ?'
            );
            $upd->execute([self::encodePgBoolArray($consumed), $row['id']]);
            return new MfaVerifyResult(
                mfaId: Id::encode('mfa', (string) $row['id']),
                type: FactorType::Recovery,
                mfaVerifiedAt: $this->now(),
            );
        });
    }

    public function getMfaPolicy(string $usrId): ?UserMfaPolicy
    {
        $userUuid = self::wireToUuid($usrId);
        $stmt = $this->pdo->prepare('SELECT id FROM usr WHERE id = ?');
        $stmt->execute([$userUuid]);
        if ($stmt->fetch(PDO::FETCH_ASSOC) === false) {
            throw new NotFoundException("User {$usrId} not found");
        }
        $stmt = $this->pdo->prepare(
            'SELECT usr_id, required, grace_until, updated_at
             FROM usr_mfa_policy WHERE usr_id = ?'
        );
        $stmt->execute([$userUuid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row !== false ? self::rowToPolicy($row) : null;
    }

    public function setMfaPolicy(
        string $usrId,
        bool $required,
        ?\DateTimeImmutable $graceUntil = null,
    ): UserMfaPolicy {
        $userUuid = self::wireToUuid($usrId);
        $stmt = $this->pdo->prepare('SELECT id FROM usr WHERE id = ?');
        $stmt->execute([$userUuid]);
        if ($stmt->fetch(PDO::FETCH_ASSOC) === false) {
            throw new NotFoundException("User {$usrId} not found");
        }
        $stmt = $this->pdo->prepare(
            'INSERT INTO usr_mfa_policy (usr_id, required, grace_until)
             VALUES (?, ?, ?)
             ON CONFLICT (usr_id) DO UPDATE SET
               required = EXCLUDED.required,
               grace_until = EXCLUDED.grace_until
             RETURNING usr_id, required, grace_until, updated_at'
        );
        $stmt->bindValue(1, $userUuid);
        $stmt->bindValue(2, $required, PDO::PARAM_BOOL);
        $stmt->bindValue(3, $graceUntil !== null ? self::fmt($graceUntil) : null);
        $stmt->execute();
        /** @var array<string, mixed> $row */
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return self::rowToPolicy($row);
    }

    /**
     * Lock and return an `mfa` row inside the current transaction.
     *
     * @return array<string, mixed>
     */
    private function lockMfa(string $mfaId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::MFA_COLS . ' FROM mfa WHERE id = ? FOR UPDATE'
        );
        $stmt->execute([self::wireToUuid($mfaId)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new NotFoundException("MFA factor {$mfaId} not found");
        }
        return $row;
    }

    /** @param array<string, mixed> $row */
    private function checkPendingNotExpired(array $row): void
    {
        if ($row['status'] !== 'pending') return;
        $expiresAt = $row['pending_expires_at'] !== null
            ? new \DateTimeImmutable((string) $row['pending_expires_at'])
            : null;
        if ($expiresAt !== null && $this->now() > $expiresAt) {
            throw new PreconditionException(
                'Pending factor ' . Id::encode('mfa', (string) $row['id']) . ' expired',
                'pending_factor_expired',
            );
        }
    }
}
