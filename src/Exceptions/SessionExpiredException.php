<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

final class SessionExpiredException extends IdentityException
{
    public function __construct(string $message)
    {
        parent::__construct($message, 'unauthorized.session_expired');
    }
}
