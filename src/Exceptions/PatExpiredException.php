<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Raised by verifyPatToken() when the PAT's expires_at is in the past
 * (ADR 0016 §"Verification semantics", step 5).
 */
final class PatExpiredException extends IdentityException
{
    public function __construct(public readonly string $patId)
    {
        parent::__construct("PAT {$patId} has expired", 'pat_expired');
    }
}
