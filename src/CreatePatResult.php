<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Success outcome of IdentityStore::createPat().
 * Token is the plaintext bearer — the ONLY opportunity to capture it.
 */
final class CreatePatResult
{
    public function __construct(
        public readonly PersonalAccessToken $pat,
        public readonly string $token,
    ) {}
}
