<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v0.2 WebAuthn primitives. Cross-SDK parity is enforced
// by the conformance corpus; these tests cover the in-SDK pieces the
// fixtures don't pin (error reasons, COSE-key edge cases, helpers).

declare(strict_types=1);

use Flametrench\Identity\Exceptions\WebAuthnException;
use Flametrench\Identity\Mfa\WebAuthn;
use Flametrench\Identity\Mfa\WebAuthnAssertionResult;

const WA_RP_ID = 'test.example';
const WA_ORIGIN = 'https://test.example';
const WA_CHALLENGE = 'unit-test-challenge';

/**
 * @return array{0: \OpenSSLAsymmetricKey, 1: string}  [private key, COSE pubkey]
 */
function waBuildKeypair(): array
{
    $pkey = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    if ($pkey === false) {
        throw new RuntimeException('openssl_pkey_new failed');
    }
    $details = openssl_pkey_get_details($pkey);
    $x = $details['ec']['x'];
    $y = $details['ec']['y'];
    return [$pkey, WebAuthn::coseKeyEs256($x, $y)];
}

function waMakeAuthData(string $rpId = WA_RP_ID, int $flags = 0x05, int $signCount = 1): string
{
    return hash('sha256', $rpId, true) . chr($flags) . pack('N', $signCount);
}

function waMakeClientData(string $challenge = WA_CHALLENGE, string $origin = WA_ORIGIN, string $type = 'webauthn.get'): string
{
    return json_encode([
        'challenge' => WebAuthn::b64urlEncode($challenge),
        'origin' => $origin,
        'type' => $type,
    ], JSON_UNESCAPED_SLASHES);
}

function waSign(\OpenSSLAsymmetricKey $pkey, string $authData, string $clientData): string
{
    $signed = $authData . hash('sha256', $clientData, true);
    openssl_sign($signed, $signature, $pkey, OPENSSL_ALGO_SHA256);
    return $signature;
}

it('verifies a well-formed assertion and returns the new count', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 42);
    $client = waMakeClientData();
    $sig = waSign($pkey, $auth, $client);
    $result = WebAuthn::verifyAssertion(
        cosePublicKey: $cose,
        storedSignCount: 10,
        storedRpId: WA_RP_ID,
        expectedChallenge: WA_CHALLENGE,
        expectedOrigin: WA_ORIGIN,
        authenticatorData: $auth,
        clientDataJson: $client,
        signature: $sig,
    );
    expect($result)->toBeInstanceOf(WebAuthnAssertionResult::class);
    expect($result->newSignCount)->toBe(42);
});

it('accepts both-zero counter (authenticator does not track)', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 0);
    $client = waMakeClientData();
    $sig = waSign($pkey, $auth, $client);
    $result = WebAuthn::verifyAssertion(
        cosePublicKey: $cose,
        storedSignCount: 0,
        storedRpId: WA_RP_ID,
        expectedChallenge: WA_CHALLENGE,
        expectedOrigin: WA_ORIGIN,
        authenticatorData: $auth,
        clientDataJson: $client,
        signature: $sig,
    );
    expect($result->newSignCount)->toBe(0);
});

it('rejects equal counter (cloned-authenticator signal)', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 10);
    $client = waMakeClientData();
    $sig = waSign($pkey, $auth, $client);
    expect(fn () => WebAuthn::verifyAssertion(
        cosePublicKey: $cose,
        storedSignCount: 10,
        storedRpId: WA_RP_ID,
        expectedChallenge: WA_CHALLENGE,
        expectedOrigin: WA_ORIGIN,
        authenticatorData: $auth,
        clientDataJson: $client,
        signature: $sig,
    ))->toThrow(WebAuthnException::class);
});

it('rejects assertion missing UV flag by default', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(flags: 0x01, signCount: 2);
    $client = waMakeClientData();
    $sig = waSign($pkey, $auth, $client);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 1,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: $auth,
            clientDataJson: $client,
            signature: $sig,
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('user_not_verified');
    }
});

it('rejects RP ID mismatch', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(rpId: 'evil.test', signCount: 2);
    $client = waMakeClientData();
    $sig = waSign($pkey, $auth, $client);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 1,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: $auth,
            clientDataJson: $client,
            signature: $sig,
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('rp_id_mismatch');
    }
});

it('rejects origin mismatch', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 2);
    $client = waMakeClientData(origin: 'https://evil.test');
    $sig = waSign($pkey, $auth, $client);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 1,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: $auth,
            clientDataJson: $client,
            signature: $sig,
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('origin_mismatch');
    }
});

it('rejects challenge mismatch', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 2);
    $client = waMakeClientData(challenge: 'different');
    $sig = waSign($pkey, $auth, $client);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 1,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: $auth,
            clientDataJson: $client,
            signature: $sig,
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('challenge_mismatch');
    }
});

it('rejects type other than webauthn.get', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 2);
    $client = waMakeClientData(type: 'webauthn.create');
    $sig = waSign($pkey, $auth, $client);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 1,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: $auth,
            clientDataJson: $client,
            signature: $sig,
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('type_mismatch');
    }
});

it('rejects tampered signature', function () {
    [$pkey, $cose] = waBuildKeypair();
    $auth = waMakeAuthData(signCount: 2);
    $client = waMakeClientData();
    $sig = waSign($pkey, $auth, $client);
    $sig[strlen($sig) - 1] = chr(ord($sig[strlen($sig) - 1]) ^ 0x01);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 1,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: $auth,
            clientDataJson: $client,
            signature: $sig,
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('signature_invalid');
    }
});

it('rejects truncated authenticatorData', function () {
    [, $cose] = waBuildKeypair();
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $cose,
            storedSignCount: 0,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: str_repeat("\x00", 10),
            clientDataJson: waMakeClientData(),
            signature: hex2bin('3006020101020101'),
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('malformed');
    }
});

it('rejects unsupported COSE kty', function () {
    $bad = "\xa5\x01\x01\x03\x26\x20\x01\x21\x58\x20" . str_repeat("\x00", 32) . "\x22\x58\x20" . str_repeat("\x00", 32);
    try {
        WebAuthn::verifyAssertion(
            cosePublicKey: $bad,
            storedSignCount: 0,
            storedRpId: WA_RP_ID,
            expectedChallenge: WA_CHALLENGE,
            expectedOrigin: WA_ORIGIN,
            authenticatorData: waMakeAuthData(),
            clientDataJson: waMakeClientData(),
            signature: hex2bin('3006020101020101'),
        );
        throw new RuntimeException('expected throw');
    } catch (WebAuthnException $e) {
        expect($e->reason)->toBe('unsupported_key');
    }
});

it('error code carries webauthn prefix', function () {
    $err = new WebAuthnException('boom', 'signature_invalid');
    expect($err->flametrenchCode)->toBe('webauthn.signature_invalid');
    expect($err->reason)->toBe('signature_invalid');
});

it('b64url roundtrip', function () {
    $bytes = "\x00\xff\xfe\xfd\xfc\xfb\xfa\xf9";
    $encoded = WebAuthn::b64urlEncode($bytes);
    expect(str_contains($encoded, '+'))->toBeFalse();
    expect(str_contains($encoded, '/'))->toBeFalse();
    expect(str_contains($encoded, '='))->toBeFalse();
});
