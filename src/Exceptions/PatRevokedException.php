<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Raised by verifyPatToken when the pat row exists but has been
 * explicitly revoked via revokePat (ADR 0016). Terminal: a revoked
 * pat cannot return to active.
 */
final class PatRevokedException extends IdentityException
{
    public function __construct(string $patId)
    {
        parent::__construct(
            "personal access token {$patId} is revoked",
            'pat.revoked',
        );
    }
}
