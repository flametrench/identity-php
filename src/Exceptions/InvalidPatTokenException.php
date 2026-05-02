<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Raised by verifyPatToken when the bearer is malformed, references a
 * non-existent pat row, or carries the wrong secret (ADR 0016).
 *
 * The "no such row" and "wrong secret" cases MUST conflate to this
 * single error class with an identical message — distinguishable
 * errors leak token-presence as a timing oracle. See ADR 0016
 * §"Verification semantics".
 */
final class InvalidPatTokenException extends IdentityException
{
    public function __construct(string $message = 'invalid personal access token')
    {
        parent::__construct($message, 'pat.invalid');
    }
}
