<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Pat;

/**
 * Server-persisted personal access token row (ADR 0016).
 *
 * The plaintext secret is NEVER carried on this object — it leaves the
 * server exactly once, in the {pat, token} tuple returned by
 * IdentityStore::createPat(). Thereafter only the owner's local copy
 * holds the secret; the server retains an Argon2id hash.
 */
final readonly class PersonalAccessToken
{
    /**
     * @param list<string> $scope Application-defined scope claims; may be empty.
     */
    public function __construct(
        public string $id,
        public string $usrId,
        public string $name,
        public array $scope,
        public PatStatus $status,
        public ?\DateTimeImmutable $expiresAt,
        public ?\DateTimeImmutable $lastUsedAt,
        public ?\DateTimeImmutable $revokedAt,
        public \DateTimeImmutable $createdAt,
        public \DateTimeImmutable $updatedAt,
    ) {}
}
