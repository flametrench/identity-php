<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

class IdentityException extends \RuntimeException
{
    public function __construct(string $message, public readonly string $flametrenchCode)
    {
        parent::__construct($message);
    }
}
