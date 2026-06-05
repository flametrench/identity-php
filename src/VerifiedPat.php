<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Success outcome of IdentityStore::verifyPatToken().
 * Carries only the fields a request-handling middleware needs to
 * populate audit + authz context.
 */
final class VerifiedPat
{
    /**
     * @param list<string> $scope
     */
    public function __construct(
        public readonly string $patId,
        public readonly string $usrId,
        public readonly array $scope,
    ) {}
}
