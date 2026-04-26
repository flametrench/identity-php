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

    /** Minimum RSA modulus per ADR 0010 / WebAuthn §5.8.5. */
    private const RSA_MIN_KEY_SIZE_BITS = 2048;

    /**
     * SPKI DER prefix for prime256v1 (P-256) EC public keys. The
     * remaining 64 bytes are the raw x || y coordinates appended after
     * the 0x04 (uncompressed point) byte already encoded here.
     */
    private const SPKI_P256_PREFIX_HEX = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';

    /**
     * SPKI DER prefix for Ed25519 public keys per RFC 8410. The
     * remaining 32 bytes are the raw public key.
     */
    private const SPKI_ED25519_PREFIX_HEX = '302a300506032b6570032100';

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

        // Algorithm dispatch per ADR 0010: COSE_Key.alg picks the verifier.
        $cose = self::parseCoseKey($cosePublicKey);
        $clientHash = hash('sha256', $clientDataJson, true);
        $signed = $authenticatorData . $clientHash;

        if ($cose['alg'] === -7) {
            $pem = self::p256SpkiPem($cose['x'], $cose['y']);
            $publicKey = openssl_pkey_get_public($pem);
            if ($publicKey === false) {
                throw new WebAuthnException('OpenSSL rejected the constructed P-256 public key', 'malformed');
            }
            if (strlen($signature) < 8 || $signature[0] !== "\x30") {
                throw new WebAuthnException('Signature is not a DER ECDSA structure', 'signature_invalid');
            }
            $result = openssl_verify($signed, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        } elseif ($cose['alg'] === -257) {
            $pem = self::rsaSpkiPem($cose['n'], $cose['e']);
            $publicKey = openssl_pkey_get_public($pem);
            if ($publicKey === false) {
                throw new WebAuthnException('OpenSSL rejected the constructed RSA public key', 'malformed');
            }
            $result = openssl_verify($signed, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        } elseif ($cose['alg'] === -8) {
            if (strlen($signature) !== 64) {
                throw new WebAuthnException(
                    'Ed25519 signature must be 64 bytes, got ' . strlen($signature),
                    'signature_invalid',
                );
            }
            // ext/sodium ships Ed25519 verification; openssl_verify gained
            // EdDSA only via OpenSSL 1.1.1+ raw mode. Sodium is the
            // portable bet across PHP 8.3 distributions.
            $ok = sodium_crypto_sign_verify_detached($signature, $signed, $cose['x']);
            $result = $ok ? 1 : 0;
        } else {
            throw new WebAuthnException(
                'Unsupported alg dispatch: ' . var_export($cose['alg'], true),
                'unsupported_key',
            );
        }

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
     * Parse a COSE_Key for any v0.2-supported algorithm. Returns a
     * shape-discriminated array keyed by `alg`.
     *
     * @return array{alg:int, x?:string, y?:string, n?:string, e?:string}
     *
     * @throws WebAuthnException
     */
    private static function parseCoseKey(string $coseKey): array
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

        if ($alg === -7) {
            if ($kty !== 2) {
                throw new WebAuthnException('ES256 requires COSE kty=2, got ' . var_export($kty, true), 'unsupported_key');
            }
            $crv = $value[-1] ?? null;
            $x = $value[-2] ?? null;
            $y = $value[-3] ?? null;
            if ($crv !== 1) {
                throw new WebAuthnException('ES256 requires crv=1, got ' . var_export($crv, true), 'unsupported_key');
            }
            if (!is_string($x) || strlen($x) !== 32) {
                throw new WebAuthnException('COSE x coordinate must be 32 bytes', 'malformed');
            }
            if (!is_string($y) || strlen($y) !== 32) {
                throw new WebAuthnException('COSE y coordinate must be 32 bytes', 'malformed');
            }
            return ['alg' => -7, 'x' => $x, 'y' => $y];
        }
        if ($alg === -257) {
            if ($kty !== 3) {
                throw new WebAuthnException('RS256 requires COSE kty=3, got ' . var_export($kty, true), 'unsupported_key');
            }
            $n = $value[-1] ?? null;
            $e = $value[-2] ?? null;
            if (!is_string($n)) {
                throw new WebAuthnException('COSE RSA modulus (n) must be a byte string', 'malformed');
            }
            if (!is_string($e)) {
                throw new WebAuthnException('COSE RSA exponent (e) must be a byte string', 'malformed');
            }
            // Compute bit-length of the modulus, ignoring leading zero bytes
            // (CBOR byte-string is unsigned big-endian; a leading 0x00 may
            // appear to disambiguate the high bit).
            $nTrimmed = ltrim($n, "\x00");
            if ($nTrimmed === '') {
                $nTrimmed = "\x00";
            }
            $msb = ord($nTrimmed[0]);
            $bits = (strlen($nTrimmed) - 1) * 8;
            for ($mask = 0x80; $mask > 0; $mask >>= 1) {
                if (($msb & $mask) !== 0) {
                    $bits += 1 + (int) log($mask, 2);
                    break;
                }
            }
            if ($bits < self::RSA_MIN_KEY_SIZE_BITS) {
                throw new WebAuthnException(
                    "RSA key {$bits}-bit is below the " . self::RSA_MIN_KEY_SIZE_BITS . '-bit floor',
                    'unsupported_key',
                );
            }
            return ['alg' => -257, 'n' => $nTrimmed, 'e' => ltrim($e, "\x00") ?: "\x00"];
        }
        if ($alg === -8) {
            if ($kty !== 1) {
                throw new WebAuthnException('EdDSA requires COSE kty=1, got ' . var_export($kty, true), 'unsupported_key');
            }
            $crv = $value[-1] ?? null;
            $x = $value[-2] ?? null;
            if ($crv !== 6) {
                throw new WebAuthnException(
                    'v0.2 EdDSA accepts only Ed25519 (crv=6), got crv=' . var_export($crv, true),
                    'unsupported_key',
                );
            }
            if (!is_string($x) || strlen($x) !== 32) {
                throw new WebAuthnException('Ed25519 public key must be 32 bytes', 'malformed');
            }
            return ['alg' => -8, 'x' => $x];
        }
        throw new WebAuthnException(
            'Unsupported COSE alg: ' . var_export($alg, true) . ' (kty=' . var_export($kty, true) . ')',
            'unsupported_key',
        );
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
     * Build a PEM-encoded SubjectPublicKeyInfo for an RSA public key
     * given the raw modulus (n) and exponent (e) bytes (big-endian,
     * leading-zero-stripped).
     */
    private static function rsaSpkiPem(string $n, string $e): string
    {
        $rsaPubDer = self::derSequence(
            self::derInteger($n) . self::derInteger($e)
        );
        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier (rsaEncryption), BIT STRING (rsaPublicKey) }
        // AlgorithmIdentifier: SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }
        $algId = hex2bin('300d06092a864886f70d0101010500');
        $bitString = "\x03" . self::derLength(strlen($rsaPubDer) + 1) . "\x00" . $rsaPubDer;
        $spki = self::derSequence($algId . $bitString);
        $b64 = chunk_split(base64_encode($spki), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n{$b64}-----END PUBLIC KEY-----\n";
    }

    /** DER INTEGER from a positive big-endian unsigned byte string. */
    private static function derInteger(string $bytes): string
    {
        // ASN.1 INTEGER is signed; if MSB is set, prepend 0x00 to keep positive.
        if ($bytes !== '' && (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $contents): string
    {
        return "\x30" . self::derLength(strlen($contents)) . $contents;
    }

    private static function derLength(int $n): string
    {
        if ($n < 128) {
            return chr($n);
        }
        $bytes = '';
        $tmp = $n;
        while ($tmp > 0) {
            $bytes = chr($tmp & 0xFF) . $bytes;
            $tmp >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
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
