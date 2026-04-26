<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity;

/**
 * Low-level Argon2id password-hashing primitives.
 *
 * Use these when you need to hash or verify a password independently of
 * the IdentityStore — e.g., to bridge legacy password stores into the
 * Flametrench identity layer, or to satisfy the cross-language
 * conformance fixture (`spec/conformance/fixtures/identity/argon2id.json`).
 *
 * The conformance contract is: a PHC-encoded Argon2id hash produced by
 * any conforming Flametrench identity SDK MUST verify identically here,
 * regardless of the language or Argon2 binding that produced it.
 */
final class PasswordHashing
{
    /**
     * Hard cap on plaintext password length before Argon2id. Most
     * password managers cap user-input passwords at 256 bytes;
     * legitimate passphrases never need 1024. Without a cap, a caller
     * can pass a multi-megabyte string and burn the Argon2id memory
     * cost (m=19 MiB) repeatedly.
     */
    public const MAX_PASSWORD_BYTES = 1024;

    private function __construct() {}

    /**
     * Verify a candidate plaintext password against a PHC-encoded
     * Argon2id hash. Returns false on any verification failure
     * (wrong password, malformed hash, unsupported variant) — never
     * throws on bad input. The contract is "did this plaintext produce
     * that hash?", and the answer to a malformed hash is "no".
     *
     * Plaintext over MAX_PASSWORD_BYTES raises InvalidArgumentException —
     * that is a caller-side input-validation failure, not a verification
     * outcome.
     */
    public static function verify(string $phcHash, string $candidatePassword): bool
    {
        self::checkPasswordLength($candidatePassword);
        // password_verify() returns false for malformed hashes without
        // raising an error, so no try/catch needed.
        return password_verify($candidatePassword, $phcHash);
    }

    /**
     * Hash a plaintext password with Argon2id at the spec floor
     * (`Argon2id::MEMORY_COST`, `TIME_COST`, `THREADS`). The returned
     * string is PHC-encoded and verifies against `verify()` on any
     * conforming Flametrench identity SDK.
     */
    public static function hash(string $plaintext): string
    {
        self::checkPasswordLength($plaintext);
        return password_hash($plaintext, PASSWORD_ARGON2ID, [
            'memory_cost' => Argon2id::MEMORY_COST,
            'time_cost' => Argon2id::TIME_COST,
            'threads' => Argon2id::THREADS,
        ]);
    }

    private static function checkPasswordLength(string $plaintext): void
    {
        $byteLength = strlen($plaintext);
        if ($byteLength > self::MAX_PASSWORD_BYTES) {
            throw new \InvalidArgumentException(
                'password exceeds ' . self::MAX_PASSWORD_BYTES
                . "-byte cap (got {$byteLength} bytes)"
            );
        }
    }
}
