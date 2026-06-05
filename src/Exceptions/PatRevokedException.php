<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Raised by verifyPatToken() when the PAT has been explicitly revoked
 * (ADR 0016 §"Verification semantics", step 4).
 */
final class PatRevokedException extends IdentityException
{
    public function __construct(public readonly string $patId)
    {
        parent::__construct("PAT {$patId} has been revoked", 'pat_revoked');
    }
}
