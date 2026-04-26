<?php

// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for v0.2 IdentityStore MFA operations. Cross-SDK parity
// is enforced by the conformance corpus and the per-primitive tests
// (TOTP RFC vectors, WebAuthn signature verification, recovery format).
// This file focuses on store-level orchestration that ADR 0008 specifies.

declare(strict_types=1);

use Flametrench\Identity\Exceptions\InvalidCredentialException;
use Flametrench\Identity\Exceptions\PreconditionException;
use Flametrench\Identity\InMemoryIdentityStore;
use Flametrench\Identity\Mfa\FactorStatus;
use Flametrench\Identity\Mfa\FactorType;
use Flametrench\Identity\Mfa\RecoveryCodes;
use Flametrench\Identity\Mfa\RecoveryProof;
use Flametrench\Identity\Mfa\Totp;
use Flametrench\Identity\Mfa\TotpProof;
use Flametrench\Identity\Mfa\WebAuthn;
use Flametrench\Identity\Mfa\WebAuthnProof;

function decodeBase32(string $s): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $clean = rtrim($s, '=');
    $bits = 0; $value = 0; $out = '';
    for ($i = 0, $n = strlen($clean); $i < $n; $i++) {
        $idx = strpos($alphabet, $clean[$i]);
        if ($idx === false) throw new RuntimeException('Invalid base32 char');
        $value = ($value << 5) | $idx;
        $bits += 5;
        if ($bits >= 8) {
            $out .= chr(($value >> ($bits - 8)) & 0xFF);
            $bits -= 8;
        }
    }
    return $out;
}

function makeMockClock(\DateTimeImmutable $start): array
{
    $state = (object) ['now' => $start];
    $clock = function () use ($state) { return $state->now; };
    $advance = function (int $seconds) use ($state) {
        $state->now = $state->now->modify("+{$seconds} seconds");
    };
    return [$clock, $advance];
}

// ─── Recovery codes ─────────────────────────────────────────────

it('recovery enrollment returns 10 codes, factor active immediately', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $result = $store->enrollRecoveryFactor($user->id);
    expect($result['factor']->status)->toBe(FactorStatus::Active);
    expect($result['codes'])->toHaveCount(10);
    foreach ($result['codes'] as $code) {
        expect(RecoveryCodes::isValid($code))->toBeTrue();
    }
    expect($result['factor']->remaining)->toBe(10);
});

it('recovery verify consumes a slot, same code is non-reusable', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $enroll = $store->enrollRecoveryFactor($user->id);
    $code = $enroll['codes'][3];
    $store->verifyMfa($user->id, new RecoveryProof($code));
    expect(fn() => $store->verifyMfa($user->id, new RecoveryProof($code)))
        ->toThrow(InvalidCredentialException::class);
    $factor = $store->getMfaFactor($enroll['factor']->id);
    expect($factor->remaining)->toBe(9);
});

it('recovery verify normalizes lowercase + whitespace', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $enroll = $store->enrollRecoveryFactor($user->id);
    $store->verifyMfa(
        $user->id,
        new RecoveryProof('  ' . strtolower($enroll['codes'][0]) . '  '),
    );
});

it('recovery: at most one active per user', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $store->enrollRecoveryFactor($user->id);
    expect(fn() => $store->enrollRecoveryFactor($user->id))
        ->toThrow(PreconditionException::class);
});

it('recovery revoke frees the singleton slot', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $first = $store->enrollRecoveryFactor($user->id);
    $store->revokeMfaFactor($first['factor']->id);
    $second = $store->enrollRecoveryFactor($user->id);
    expect($second['factor']->id)->not->toBe($first['factor']->id);
});

// ─── TOTP ────────────────────────────────────────────────────────

it('TOTP enrollment returns pending factor + secret + otpauth URI', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $enroll = $store->enrollTotpFactor($user->id, 'iPhone');
    expect($enroll['factor']->status)->toBe(FactorStatus::Pending);
    expect($enroll['secretB32'])->toMatch('/^[A-Z2-7]+$/');
    expect($enroll['otpauthUri'])->toStartWith('otpauth://totp/');
});

it('TOTP confirm with current code activates the factor', function () {
    [$clock] = makeMockClock(new DateTimeImmutable('2026-04-26T12:00:00Z'));
    $store = new InMemoryIdentityStore(clock: $clock);
    $user = $store->createUser();
    $enroll = $store->enrollTotpFactor($user->id, 'iPhone');
    $secret = decodeBase32($enroll['secretB32']);
    $code = Totp::compute($secret, $clock()->getTimestamp());
    $confirmed = $store->confirmTotpFactor($enroll['factor']->id, $code);
    expect($confirmed->status)->toBe(FactorStatus::Active);
});

it('TOTP confirm with wrong code rejects', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $enroll = $store->enrollTotpFactor($user->id, 'iPhone');
    expect(fn() => $store->confirmTotpFactor($enroll['factor']->id, '000000'))
        ->toThrow(InvalidCredentialException::class);
});

it('TOTP confirm after pending TTL rejects', function () {
    [$clock, $advance] = makeMockClock(new DateTimeImmutable('2026-04-26T12:00:00Z'));
    $store = new InMemoryIdentityStore(clock: $clock);
    $user = $store->createUser();
    $enroll = $store->enrollTotpFactor($user->id, 'iPhone');
    $advance(700);
    $secret = decodeBase32($enroll['secretB32']);
    $code = Totp::compute($secret, $clock()->getTimestamp());
    try {
        $store->confirmTotpFactor($enroll['factor']->id, $code);
        throw new RuntimeException('expected throw');
    } catch (PreconditionException $e) {
        expect($e->specifics)->toBe('pending_factor_expired');
    }
});

it('TOTP at most one active per user (after confirm)', function () {
    [$clock] = makeMockClock(new DateTimeImmutable('2026-04-26T12:00:00Z'));
    $store = new InMemoryIdentityStore(clock: $clock);
    $user = $store->createUser();
    $enroll = $store->enrollTotpFactor($user->id, 'iPhone');
    $secret = decodeBase32($enroll['secretB32']);
    $store->confirmTotpFactor(
        $enroll['factor']->id,
        Totp::compute($secret, $clock()->getTimestamp()),
    );
    expect(fn() => $store->enrollTotpFactor($user->id, 'Backup'))
        ->toThrow(PreconditionException::class);
});

it('TOTP verify after confirm returns type=totp', function () {
    [$clock] = makeMockClock(new DateTimeImmutable('2026-04-26T12:00:00Z'));
    $store = new InMemoryIdentityStore(clock: $clock);
    $user = $store->createUser();
    $enroll = $store->enrollTotpFactor($user->id, 'iPhone');
    $secret = decodeBase32($enroll['secretB32']);
    $store->confirmTotpFactor(
        $enroll['factor']->id,
        Totp::compute($secret, $clock()->getTimestamp()),
    );
    $result = $store->verifyMfa(
        $user->id,
        new TotpProof(Totp::compute($secret, $clock()->getTimestamp())),
    );
    expect($result->type)->toBe(FactorType::Totp);
    expect($result->mfaId)->toBe($enroll['factor']->id);
});

it('TOTP verify with no active factor rejects', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    expect(fn() => $store->verifyMfa($user->id, new TotpProof('123456')))
        ->toThrow(InvalidCredentialException::class);
});

// ─── WebAuthn ────────────────────────────────────────────────────

function makeKeypairAndCose(): array
{
    $pkey = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1',
    ]);
    $details = openssl_pkey_get_details($pkey);
    $cose = WebAuthn::coseKeyEs256($details['ec']['x'], $details['ec']['y']);
    return [$pkey, $cose];
}

function makeAssertion(
    \OpenSSLAsymmetricKey $pkey,
    string $rpId,
    string $origin,
    string $challenge,
    int $signCount,
): array {
    $rpHash = hash('sha256', $rpId, true);
    $authData = $rpHash . chr(0x05) . pack('N', $signCount);
    $clientData = json_encode([
        'challenge' => WebAuthn::b64urlEncode($challenge),
        'origin' => $origin,
        'type' => 'webauthn.get',
    ], JSON_UNESCAPED_SLASHES);
    $signed = $authData . hash('sha256', $clientData, true);
    openssl_sign($signed, $signature, $pkey, OPENSSL_ALGO_SHA256);
    return [$authData, $clientData, $signature];
}

it('WebAuthn enroll → confirm → verify advances counter', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    [$pkey, $cose] = makeKeypairAndCose();
    $credId = 'test-credential-id';
    $rpId = 'test.example';
    $origin = 'https://test.example';
    $enroll = $store->enrollWebAuthnFactor(
        usrId: $user->id, identifier: $credId,
        publicKey: $cose, signCount: 0, rpId: $rpId,
    );
    expect($enroll['factor']->status)->toBe(FactorStatus::Pending);
    [$ad1, $cd1, $sig1] = makeAssertion($pkey, $rpId, $origin, 'confirm-challenge', 1);
    $confirmed = $store->confirmWebAuthnFactor(
        mfaId: $enroll['factor']->id,
        authenticatorData: $ad1, clientDataJson: $cd1, signature: $sig1,
        expectedChallenge: 'confirm-challenge', expectedOrigin: $origin,
    );
    expect($confirmed->status)->toBe(FactorStatus::Active);
    expect($confirmed->signCount)->toBe(1);
    [$ad2, $cd2, $sig2] = makeAssertion($pkey, $rpId, $origin, 'verify-challenge', 2);
    $result = $store->verifyMfa($user->id, new WebAuthnProof(
        credentialId: $credId,
        authenticatorData: $ad2, clientDataJson: $cd2, signature: $sig2,
        expectedChallenge: 'verify-challenge', expectedOrigin: $origin,
    ));
    expect($result->type)->toBe(FactorType::WebAuthn);
    expect($result->newSignCount)->toBe(2);
});

it('WebAuthn multiple active factors permitted per user', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    [, $cose1] = makeKeypairAndCose();
    [, $cose2] = makeKeypairAndCose();
    $a = $store->enrollWebAuthnFactor(
        usrId: $user->id, identifier: 'cred-a',
        publicKey: $cose1, signCount: 0, rpId: 'x',
    );
    $b = $store->enrollWebAuthnFactor(
        usrId: $user->id, identifier: 'cred-b',
        publicKey: $cose2, signCount: 0, rpId: 'x',
    );
    expect($a['factor']->id)->not->toBe($b['factor']->id);
});

it('WebAuthn duplicate credential id rejects', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    [, $cose] = makeKeypairAndCose();
    $store->enrollWebAuthnFactor(
        usrId: $user->id, identifier: 'dup',
        publicKey: $cose, signCount: 0, rpId: 'x',
    );
    expect(fn() => $store->enrollWebAuthnFactor(
        usrId: $user->id, identifier: 'dup',
        publicKey: $cose, signCount: 0, rpId: 'x',
    ))->toThrow(PreconditionException::class);
});

// ─── Listing + policy ───

it('listMfaFactors returns user-scoped set', function () {
    $store = new InMemoryIdentityStore();
    $a = $store->createUser();
    $b = $store->createUser();
    $store->enrollRecoveryFactor($a->id);
    $store->enrollTotpFactor($a->id, 'iPhone');
    $store->enrollRecoveryFactor($b->id);
    expect($store->listMfaFactors($a->id))->toHaveCount(2);
    expect($store->listMfaFactors($b->id))->toHaveCount(1);
});

it('mfa policy defaults to null', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    expect($store->getMfaPolicy($user->id))->toBeNull();
});

it('mfa policy set then get round-trip', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $grace = new DateTimeImmutable('2026-05-10T00:00:00Z');
    $policy = $store->setMfaPolicy($user->id, required: true, graceUntil: $grace);
    expect($policy->required)->toBeTrue();
    expect($policy->graceUntil->format('c'))->toBe($grace->format('c'));
    $fetched = $store->getMfaPolicy($user->id);
    expect($fetched)->toEqual($policy);
});

it('mfa policy set overwrites the row', function () {
    $store = new InMemoryIdentityStore();
    $user = $store->createUser();
    $store->setMfaPolicy($user->id, required: true);
    $store->setMfaPolicy($user->id, required: false);
    expect($store->getMfaPolicy($user->id)->required)->toBeFalse();
});
