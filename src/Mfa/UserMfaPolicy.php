<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Per-user MFA enforcement policy.
 *
 * When required is true and graceUntil is null or past, verifyPassword
 * produces an MFA-required signal instead of minting a session directly.
 */
final readonly class UserMfaPolicy
{
    public function __construct(
        public string $usrId,
        public bool $required,
        public ?\DateTimeImmutable $graceUntil,
        public \DateTimeImmutable $updatedAt,
    ) {}

    /** True when MFA enforcement is active for this user as of $now. */
    public function isActiveNow(\DateTimeImmutable $now): bool
    {
        if (!$this->required) {
            return false;
        }
        if ($this->graceUntil === null) {
            return true;
        }
        return $now >= $this->graceUntil;
    }
}
