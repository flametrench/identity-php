<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Pat;

/**
 * Successful result of {@see \Flametrench\Identity\IdentityStore::verifyPatToken}.
 *
 * Carries only the fields a request-handling middleware needs to
 * populate audit + authz context: the pat id (audit handle), the
 * usr_id (the principal the request acts as), and the scope (the
 * application-defined claims attached to this token).
 *
 * The plaintext token is never returned here — by this point the
 * verifier has already discarded it.
 */
final readonly class VerifiedPat
{
    /**
     * @param list<string> $scope Application-defined scope claims; may be empty.
     */
    public function __construct(
        public string $patId,
        public string $usrId,
        public array $scope,
    ) {}
}
