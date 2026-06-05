<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

enum PatStatus: string
{
    case Active  = 'active';
    case Expired = 'expired';
    case Revoked = 'revoked';
}
