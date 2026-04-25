<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

enum CredentialType: string
{
    case Password = 'password';
    case Passkey = 'passkey';
    case Oidc = 'oidc';
}
