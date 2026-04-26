<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

/**
 * RFC 6238 Time-based One-Time Password primitives.
 *
 * Pure-static: no instance state. The algorithm is deterministic and
 * exhaustively spec'd; cross-SDK byte-identical against the same RFC
 * vectors as the Python and Node SDKs.
 */
final class Totp
{
    public const DEFAULT_PERIOD = 30;
    public const DEFAULT_DIGITS = 6;
    public const DEFAULT_ALGORITHM = 'sha1';

    private function __construct() {}

    /**
     * Compute the TOTP code for a given secret and timestamp.
     *
     * @param  string  $secret  Raw shared-secret bytes (NOT base32-encoded).
     */
    public static function compute(
        string $secret,
        int $timestamp,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS,
        string $algorithm = self::DEFAULT_ALGORITHM,
    ): string {
        $counter = intdiv($timestamp, $period);
        // Pack as 8-byte big-endian. PHP doesn't have a built-in
        // 64-bit BE pack on all platforms; use J (unsigned long long
        // big-endian) which has been cross-platform since PHP 5.6.
        $counterBytes = pack('J', $counter);
        $digest = hash_hmac($algorithm, $counterBytes, $secret, true);
        $offset = ord($digest[strlen($digest) - 1]) & 0x0F;
        $codeInt = (
            ((ord($digest[$offset]) & 0x7F) << 24) |
            ((ord($digest[$offset + 1]) & 0xFF) << 16) |
            ((ord($digest[$offset + 2]) & 0xFF) << 8) |
            (ord($digest[$offset + 3]) & 0xFF)
        );
        return str_pad((string) ($codeInt % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a candidate TOTP code with drift tolerance.
     *
     * Accepts the current window plus ±$driftWindows surrounding
     * windows (default ±1). Constant-time compared via hash_equals.
     */
    public static function verify(
        string $secret,
        string $candidate,
        ?int $timestamp = null,
        int $period = self::DEFAULT_PERIOD,
        int $digits = self::DEFAULT_DIGITS,
        string $algorithm = self::DEFAULT_ALGORITHM,
        int $driftWindows = 1,
    ): bool {
        if ($driftWindows < 0 || $driftWindows > 10) {
            // Cap the verifier search radius. Each window adds one HMAC
            // computation, so unbounded values amount to a CPU-exhaustion
            // primitive. The default ±1 covers normal clock skew; ±10 is
            // the operational ceiling.
            throw new \InvalidArgumentException(
                "driftWindows must be 0..10, got {$driftWindows}",
            );
        }
        if ($timestamp === null) {
            $timestamp = time();
        }
        if (
            $candidate === ''
            || strlen($candidate) !== $digits
            || preg_match('/^[0-9]+$/', $candidate) !== 1
        ) {
            return false;
        }
        for ($w = -$driftWindows; $w <= $driftWindows; $w++) {
            $ts = $timestamp + ($w * $period);
            $expected = self::compute($secret, $ts, $period, $digits, $algorithm);
            if (hash_equals($expected, $candidate)) {
                return true;
            }
        }
        return false;
    }

    /** Generate a fresh TOTP shared secret. Default 20 bytes per RFC 6238. */
    public static function generateSecret(int $numBytes = 20): string
    {
        return random_bytes($numBytes);
    }

    /** Build the otpauth:// URI for QR rendering at enrollment. */
    public static function otpauthUri(
        string $secret,
        string $label,
        string $issuer,
        string $algorithm = self::DEFAULT_ALGORITHM,
        int $digits = self::DEFAULT_DIGITS,
        int $period = self::DEFAULT_PERIOD,
    ): string {
        $secretB32 = rtrim(self::base32Encode($secret), '=');
        $labelQ = rawurlencode("{$issuer}:{$label}");
        $issuerQ = rawurlencode($issuer);
        return "otpauth://totp/{$labelQ}"
            . "?secret={$secretB32}"
            . "&issuer={$issuerQ}"
            . '&algorithm=' . strtoupper($algorithm)
            . "&digits={$digits}"
            . "&period={$period}";
    }

    /** RFC 4648 base32 encoding (with padding). */
    private static function base32Encode(string $buf): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = 0;
        $value = 0;
        $out = '';
        $len = strlen($buf);
        for ($i = 0; $i < $len; $i++) {
            $value = ($value << 8) | ord($buf[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $out .= $alphabet[($value >> ($bits - 5)) & 0x1F];
                $bits -= 5;
            }
        }
        if ($bits > 0) {
            $out .= $alphabet[($value << (5 - $bits)) & 0x1F];
        }
        while (strlen($out) % 8 !== 0) {
            $out .= '=';
        }
        return $out;
    }
}
