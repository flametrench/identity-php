<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Audit `auth.kind` discriminator per ADR 0016 §"Bearer routing".
 * Identifies the bearer-credential type on every authenticated request.
 */
enum AuthKind: string
{
    case Pat     = 'pat';
    case Share   = 'share';
    case Session = 'session';
    case System  = 'system';
}
