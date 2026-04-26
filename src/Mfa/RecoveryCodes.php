<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * Recovery code primitives.
 *
 * 12-character codes in three groups of four, separated by hyphens.
 * The 31-char alphabet excludes 0/O/1/I/L for reading clarity.
 */
final class RecoveryCodes
{
    public const COUNT = 10;
    public const LENGTH = 12;
    private const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

    private function __construct() {}

    /** Generate one fresh 12-char recovery code, formatted XXXX-XXXX-XXXX. */
    public static function generate(): string
    {
        $alphabet = self::ALPHABET;
        $alphabetLen = strlen($alphabet);
        $chars = '';
        for ($i = 0; $i < self::LENGTH; $i++) {
            $chars .= $alphabet[random_int(0, $alphabetLen - 1)];
        }
        return substr($chars, 0, 4) . '-' . substr($chars, 4, 4) . '-' . substr($chars, 8, 4);
    }

    /**
     * Generate a fresh set of 10 recovery codes.
     *
     * @return list<string>
     */
    public static function generateSet(): array
    {
        return array_map(
            fn(int $_): string => self::generate(),
            range(1, self::COUNT),
        );
    }

    /**
     * Normalize user-input recovery code: uppercase + strip whitespace.
     * Hyphens are preserved.
     */
    public static function normalizeInput(string $code): string
    {
        return strtoupper(trim($code));
    }

    /**
     * Predicate: does $code match the canonical 12-char three-group form?
     *
     * True iff:
     *   - exactly 14 chars (12 alphabet + 2 hyphens)
     *   - three groups of four, hyphen-separated
     *   - every char from the recovery alphabet (excludes 0/O/1/I/L)
     *   - all chars uppercase ASCII
     */
    public static function isValid(string $code): bool
    {
        if (strlen($code) !== self::LENGTH + 2) {
            return false;
        }
        $parts = explode('-', $code);
        if (count($parts) !== 3) {
            return false;
        }
        foreach ($parts as $part) {
            if (strlen($part) !== 4) {
                return false;
            }
            $partLen = strlen($part);
            for ($i = 0; $i < $partLen; $i++) {
                if (strpos(self::ALPHABET, $part[$i]) === false) {
                    return false;
                }
            }
        }
        return true;
    }
}
