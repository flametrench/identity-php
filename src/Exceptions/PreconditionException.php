<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Exceptions;

final class PreconditionException extends IdentityException
{
    public function __construct(string $message, public readonly string $specifics)
    {
        parent::__construct($message, "precondition.{$specifics}");
    }
}
