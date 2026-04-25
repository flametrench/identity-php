<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Marker interface for the three credential variants. PHP doesn't have
 * discriminated unions; callers use `instanceof` to narrow to a concrete
 * type, or check the `$type` property.
 */
interface Credential
{
    public function getId(): string;
    public function getUsrId(): string;
    public function getType(): CredentialType;
    public function getIdentifier(): string;
    public function getStatus(): Status;
    public function getReplaces(): ?string;
    public function getCreatedAt(): \DateTimeImmutable;
    public function getUpdatedAt(): \DateTimeImmutable;
}
