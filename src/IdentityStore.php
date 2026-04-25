<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Contract every identity backend implements.
 *
 * Cascade guarantees (spec-required):
 *   - Revoking a user revokes every active credential AND terminates
 *     every active session.
 *   - Suspending a user terminates active sessions but preserves creds.
 *   - Rotating a credential terminates every session bound to the old.
 *   - Revoking or suspending a credential terminates every session
 *     bound to it.
 */
interface IdentityStore
{
    // ─── Users ───
    public function createUser(): User;
    public function getUser(string $usrId): User;
    public function suspendUser(string $usrId): User;
    public function reinstateUser(string $usrId): User;
    public function revokeUser(string $usrId): User;

    // ─── Credentials ───
    public function createPasswordCredential(
        string $usrId,
        string $identifier,
        string $password,
    ): PasswordCredential;

    public function createPasskeyCredential(
        string $usrId,
        string $identifier,
        string $publicKey,
        int $signCount,
        string $rpId,
    ): PasskeyCredential;

    public function createOidcCredential(
        string $usrId,
        string $identifier,
        string $oidcIssuer,
        string $oidcSubject,
    ): OidcCredential;

    public function getCredential(string $credId): Credential;

    /** @return list<Credential> */
    public function listCredentialsForUser(string $usrId): array;

    public function findCredentialByIdentifier(
        CredentialType $type,
        string $identifier,
    ): ?Credential;

    public function rotatePassword(string $credId, string $newPassword): PasswordCredential;
    public function rotatePasskey(string $credId, string $publicKey, int $signCount, string $rpId): PasskeyCredential;
    public function rotateOidc(string $credId, string $oidcIssuer, string $oidcSubject): OidcCredential;

    public function suspendCredential(string $credId): Credential;
    public function reinstateCredential(string $credId): Credential;
    public function revokeCredential(string $credId): Credential;

    public function verifyPassword(string $identifier, string $password): VerifiedCredential;

    // ─── Sessions ───
    public function createSession(string $usrId, string $credId, int $ttlSeconds): SessionWithToken;
    public function getSession(string $sesId): Session;

    /** @return Page<Session> */
    public function listSessionsForUser(string $usrId, ?string $cursor = null, int $limit = 50): Page;

    public function verifySessionToken(string $token): Session;

    public function refreshSession(string $sesId): SessionWithToken;
    public function revokeSession(string $sesId): Session;
}
