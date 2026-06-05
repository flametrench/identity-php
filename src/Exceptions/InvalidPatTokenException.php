<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

/**
 * Raised by verifyPatToken() when the token is structurally invalid, the
 * pat_id is not found, or the secret does not match.  Conflates
 * "no such PAT" with "wrong secret" to avoid a timing-oracle that would
 * distinguish the two (ADR 0016 §"Verification semantics").
 */
final class InvalidPatTokenException extends IdentityException
{
    public function __construct(string $message = 'Invalid PAT token')
    {
        parent::__construct($message, 'invalid_pat_token');
    }
}
