<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Flametrench\Identity\Mfa;

use Flametrench\Identity\Exceptions\WebAuthnException;

/**
 * WebAuthn assertion verification — v0.2 reference per ADR 0008.
 *
 * Mirrors identity-python's webauthn module exactly so the conformance
 * fixture corpus passes byte-identically across SDKs. Pure-static.
 *
 * Scope (v0.2): ES256 (ECDSA P-256 + SHA-256) only. RS256 + EdDSA are
 * deferred to v0.3.
 */
final class WebAuthn
{
    private const FLAG_UP = 0x01;
    private const FLAG_UV = 0x04;

    /**
     * SPKI DER prefix for prime256v1 (P-256) EC public keys. The
     * remaining 64 bytes are the raw x || y coordinates appended after
     * the 0x04 (uncompressed point) byte already encoded here.
     */
    private const SPKI_P256_PREFIX_HEX = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';

    private function __construct() {}

    /**
     * Verify a WebAuthn assertion and return the new sign count.
     *
     * @param  string  $cosePublicKey  Raw COSE_Key bytes from registration. v0.2 supports ES256 only.
     * @param  int  $storedSignCount  Counter recorded on the last successful assertion.
     * @param  string  $storedRpId  RP ID the credential was registered for.
     * @param  string  $expectedChallenge  Raw challenge bytes the application issued.
     * @param  string  $expectedOrigin  Origin the application expects (e.g. "https://example.com").
     * @param  string  $authenticatorData  AuthenticatorAssertionResponse.authenticatorData bytes.
     * @param  string  $clientDataJson  AuthenticatorAssertionResponse.clientDataJSON bytes.
     * @param  string  $signature  AuthenticatorAssertionResponse.signature (DER ECDSA for ES256).
     * @param  bool  $requireUserVerified  When true (default), reject assertions lacking the UV bit.
     * @param  bool  $requireUserPresent  When true (default), reject assertions lacking the UP bit.
     *
     * @throws WebAuthnException on any failure.
     */
    public static function verifyAssertion(
        string $cosePublicKey,
        int $storedSignCount,
        string $storedRpId,
        string $expectedChallenge,
        string $expectedOrigin,
        string $authenticatorData,
        string $clientDataJson,
        string $signature,
        bool $requireUserVerified = true,
        bool $requireUserPresent = true,
    ): WebAuthnAssertionResult {
        // Parse clientDataJSON.
        $clientData = json_decode($clientDataJson, associative: true);
        if (!is_array($clientData)) {
            throw new WebAuthnException(
                'clientDataJSON not valid JSON object',
                'malformed',
            );
        }
        $type = $clientData['type'] ?? null;
        if ($type !== 'webauthn.get') {
            throw new WebAuthnException(
                "clientDataJSON.type must be 'webauthn.get', got " . var_export($type, true),
                'type_mismatch',
            );
        }
        $origin = $clientData['origin'] ?? null;
        if ($origin !== $expectedOrigin) {
            throw new WebAuthnException(
                "Origin mismatch: expected {$expectedOrigin}, got " . var_export($origin, true),
                'origin_mismatch',
            );
        }
        $challengeB64u = $clientData['challenge'] ?? null;
        if (!is_string($challengeB64u)) {
            throw new WebAuthnException(
                'clientDataJSON.challenge missing or not a string',
                'malformed',
            );
        }
        $challengeBytes = self::b64urlDecode($challengeB64u);
        if ($challengeBytes === false) {
            throw new WebAuthnException(
                'clientDataJSON.challenge not base64url',
                'malformed',
            );
        }
        if (!hash_equals($expectedChallenge, $challengeBytes)) {
            throw new WebAuthnException('Challenge does not match', 'challenge_mismatch');
        }

        // Parse authenticatorData.
        if (strlen($authenticatorData) < 37) {
            throw new WebAuthnException('authenticatorData truncated', 'malformed');
        }
        $rpIdHash = substr($authenticatorData, 0, 32);
        $flags = ord($authenticatorData[32]);
        // Big-endian uint32 from bytes 33..36.
        $signCount = unpack('N', substr($authenticatorData, 33, 4))[1];

        $expectedRpHash = hash('sha256', $storedRpId, true);
        if (!hash_equals($expectedRpHash, $rpIdHash)) {
            throw new WebAuthnException('RP ID hash does not match', 'rp_id_mismatch');
        }
        if ($requireUserPresent && ($flags & self::FLAG_UP) === 0) {
            throw new WebAuthnException('User-present flag not set', 'user_not_present');
        }
        if ($requireUserVerified && ($flags & self::FLAG_UV) === 0) {
            throw new WebAuthnException('User-verified flag not set', 'user_not_verified');
        }

        // Counter monotonicity (WebAuthn §6.1.1).
        if ($signCount === 0 && $storedSignCount === 0) {
            $newSignCount = 0;
        } elseif ($signCount > $storedSignCount) {
            $newSignCount = $signCount;
        } else {
            throw new WebAuthnException(
                "Sign count did not advance: stored={$storedSignCount}, got={$signCount}",
                'counter_regression',
            );
        }

        // Parse COSE_Key, build SPKI DER, verify ES256 signature.
        [$x, $y] = self::parseCoseEs256($cosePublicKey);
        $pem = self::p256SpkiPem($x, $y);
        $publicKey = openssl_pkey_get_public($pem);
        if ($publicKey === false) {
            throw new WebAuthnException('OpenSSL rejected the constructed P-256 public key', 'malformed');
        }

        if (strlen($signature) < 8 || $signature[0] !== "\x30") {
            throw new WebAuthnException('Signature is not a DER ECDSA structure', 'signature_invalid');
        }

        $clientHash = hash('sha256', $clientDataJson, true);
        $signed = $authenticatorData . $clientHash;
        $result = openssl_verify($signed, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            throw new WebAuthnException(
                $result === -1
                    ? ('openssl_verify error: ' . (openssl_error_string() ?: 'unknown'))
                    : 'Signature verification failed',
                'signature_invalid',
            );
        }

        return new WebAuthnAssertionResult($newSignCount);
    }

    /**
     * Build a COSE_Key (RFC 8152) for an ES256 / P-256 public key from raw
     * 32-byte x/y coordinates. Useful for fixture authoring.
     */
    public static function coseKeyEs256(string $x, string $y): string
    {
        if (strlen($x) !== 32 || strlen($y) !== 32) {
            throw new \InvalidArgumentException('ES256 coordinates must be 32 bytes each');
        }
        return "\xa5"
            . "\x01\x02"
            . "\x03\x26"
            . "\x20\x01"
            . "\x21\x58\x20" . $x
            . "\x22\x58\x20" . $y;
    }

    /**
     * @return array{0: string, 1: string} [x, y] each 32 bytes.
     *
     * @throws WebAuthnException
     */
    private static function parseCoseEs256(string $coseKey): array
    {
        $cursor = 0;
        $value = self::cborDecodeItem($coseKey, $cursor);
        if ($cursor !== strlen($coseKey)) {
            throw new WebAuthnException('Trailing bytes after CBOR map', 'malformed');
        }
        if (!is_array($value)) {
            throw new WebAuthnException('Top-level COSE value is not a map', 'malformed');
        }
        $kty = $value[1] ?? null;
        $alg = $value[3] ?? null;
        $crv = $value[-1] ?? null;
        $x = $value[-2] ?? null;
        $y = $value[-3] ?? null;
        if ($kty !== 2) {
            throw new WebAuthnException('Unsupported COSE kty: ' . var_export($kty, true), 'unsupported_key');
        }
        if ($alg !== -7) {
            throw new WebAuthnException('Unsupported COSE alg: ' . var_export($alg, true), 'unsupported_key');
        }
        if ($crv !== 1) {
            throw new WebAuthnException('Unsupported COSE crv: ' . var_export($crv, true), 'unsupported_key');
        }
        if (!is_string($x) || strlen($x) !== 32) {
            throw new WebAuthnException('COSE x coordinate must be 32 bytes', 'malformed');
        }
        if (!is_string($y) || strlen($y) !== 32) {
            throw new WebAuthnException('COSE y coordinate must be 32 bytes', 'malformed');
        }
        return [$x, $y];
    }

    /**
     * Decode one CBOR item. Supports the subset needed for ES256 COSE keys:
     * unsigned int, negative int, byte string, map (small-int keys).
     *
     * @return int|string|array<int, mixed>
     *
     * @throws WebAuthnException
     */
    private static function cborDecodeItem(string $buf, int &$cursor): int|string|array
    {
        if ($cursor >= strlen($buf)) {
            throw new WebAuthnException('CBOR truncated', 'malformed');
        }
        $first = ord($buf[$cursor++]);
        $major = $first >> 5;
        $info = $first & 0x1F;
        $uintReader = function () use (&$cursor, $buf, $info): int {
            if ($info < 24) {
                return $info;
            }
            if ($info === 24) {
                if ($cursor >= strlen($buf)) {
                    throw new WebAuthnException('CBOR truncated', 'malformed');
                }
                return ord($buf[$cursor++]);
            }
            if ($info === 25) {
                if ($cursor + 2 > strlen($buf)) {
                    throw new WebAuthnException('CBOR truncated', 'malformed');
                }
                $v = unpack('n', substr($buf, $cursor, 2))[1];
                $cursor += 2;
                return $v;
            }
            if ($info === 26) {
                if ($cursor + 4 > strlen($buf)) {
                    throw new WebAuthnException('CBOR truncated', 'malformed');
                }
                $v = unpack('N', substr($buf, $cursor, 4))[1];
                $cursor += 4;
                return $v;
            }
            // 64-bit lengths unrealistic for COSE keys.
            throw new WebAuthnException('Unsupported CBOR length encoding', 'malformed');
        };
        if ($major === 0) {
            return $uintReader();
        }
        if ($major === 1) {
            return -1 - $uintReader();
        }
        if ($major === 2) {
            $length = $uintReader();
            if ($cursor + $length > strlen($buf)) {
                throw new WebAuthnException('CBOR truncated', 'malformed');
            }
            $bytes = substr($buf, $cursor, $length);
            $cursor += $length;
            return $bytes;
        }
        if ($major === 5) {
            $length = $uintReader();
            $out = [];
            for ($i = 0; $i < $length; $i++) {
                $key = self::cborDecodeItem($buf, $cursor);
                $val = self::cborDecodeItem($buf, $cursor);
                if (!is_int($key)) {
                    throw new WebAuthnException('Non-int CBOR map key', 'malformed');
                }
                $out[$key] = $val;
            }
            return $out;
        }
        throw new WebAuthnException("Unsupported CBOR major type: {$major}", 'malformed');
    }

    /**
     * Build a PEM-encoded SubjectPublicKeyInfo for a P-256 public key
     * given the raw 32-byte x/y coordinates.
     */
    private static function p256SpkiPem(string $x, string $y): string
    {
        $der = hex2bin(self::SPKI_P256_PREFIX_HEX) . $x . $y;
        $b64 = chunk_split(base64_encode($der), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n{$b64}-----END PUBLIC KEY-----\n";
    }

    /**
     * @return string|false
     */
    private static function b64urlDecode(string $s): string|false
    {
        $padded = $s . str_repeat('=', (4 - strlen($s) % 4) % 4);
        $std = strtr($padded, '-_', '+/');
        return base64_decode($std, strict: true);
    }

    public static function b64urlEncode(string $buf): string
    {
        return rtrim(strtr(base64_encode($buf), '+/', '-_'), '=');
    }
}
