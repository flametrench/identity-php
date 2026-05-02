<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Raised by verifyPatToken when the pat row exists, has not been
 * revoked, but is past its expires_at (ADR 0016).
 */
final class PatExpiredException extends IdentityException
{
    public function __construct(string $patId)
    {
        parent::__construct(
            "personal access token {$patId} is expired",
            'pat.expired',
        );
    }
}
