<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Server-persisted PAT record returned by createPat / getPat / listPatsForUser / revokePat.
 *
 * The secret is NEVER present here — only the Argon2id hash is stored, and
 * only the plaintext token returned once from createPat. After that the
 * owner's local copy is the only place it exists (per ADR 0016).
 */
final class PersonalAccessToken
{
    /**
     * @param list<string> $scope
     */
    public function __construct(
        public readonly string $id,
        public readonly string $usrId,
        public readonly string $name,
        public readonly array $scope,
        public readonly PatStatus $status,
        public readonly ?\DateTimeImmutable $expiresAt,
        public readonly ?\DateTimeImmutable $lastUsedAt,
        public readonly ?\DateTimeImmutable $revokedAt,
        public readonly \DateTimeImmutable $createdAt,
        public readonly \DateTimeImmutable $updatedAt,
    ) {}
}
