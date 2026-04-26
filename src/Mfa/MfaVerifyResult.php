<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Returned by ``IdentityStore::verifyMfa`` on success.
 *
 * `newSignCount` is set only for WebAuthn proofs.
 * `mfaVerifiedAt` is the timestamp the SDK stamps on the session
 * (per ADR 0008 ``ses.mfa_verified_at``).
 */
final readonly class MfaVerifyResult
{
    public function __construct(
        public string $mfaId,
        public FactorType $type,
        public \DateTimeImmutable $mfaVerifiedAt,
        public ?int $newSignCount = null,
    ) {}
}
