import pytest

from nacl.signing import SigningKey

from securechat.kex import generate_private_key, public_key
from securechat.kex_auth import (
    KEX_CONTEXT,
    establish_authenticated_session_key,
    generate_signed_ephemeral_key,
    verify_signed_ephemeral_key,
)


def test_signed_ephemeral_key_verifies():
    identity = SigningKey.generate()
    ephemeral_private = generate_private_key()

    ephemeral_public, signature = generate_signed_ephemeral_key(
        identity,
        ephemeral_private,
    )

    assert verify_signed_ephemeral_key(
        identity.verify_key,
        ephemeral_public,
        signature,
    )


def test_tampered_ephemeral_key_is_rejected():
    identity = SigningKey.generate()
    ephemeral_private = generate_private_key()

    ephemeral_public, signature = generate_signed_ephemeral_key(
        identity,
        ephemeral_private,
    )

    tampered = bytearray(ephemeral_public)
    tampered[0] ^= 1

    assert not verify_signed_ephemeral_key(
        identity.verify_key,
        bytes(tampered),
        signature,
    )


def test_wrong_identity_is_rejected():
    identity = SigningKey.generate()
    wrong_identity = SigningKey.generate()
    ephemeral_private = generate_private_key()

    ephemeral_public, signature = generate_signed_ephemeral_key(
        identity,
        ephemeral_private,
    )

    assert not verify_signed_ephemeral_key(
        wrong_identity.verify_key,
        ephemeral_public,
        signature,
    )


def test_tampered_signature_is_rejected():
    identity = SigningKey.generate()
    ephemeral_private = generate_private_key()

    ephemeral_public, signature = generate_signed_ephemeral_key(
        identity,
        ephemeral_private,
    )

    tampered = bytearray(signature)
    tampered[-1] ^= 1

    assert not verify_signed_ephemeral_key(
        identity.verify_key,
        ephemeral_public,
        bytes(tampered),
    )


def test_authenticated_session_keys_match():
    alice_identity = SigningKey.generate()
    bob_identity = SigningKey.generate()

    alice_ephemeral_private = generate_private_key()
    bob_ephemeral_private = generate_private_key()

    alice_ephemeral_public, alice_signature = (
        generate_signed_ephemeral_key(
            alice_identity,
            alice_ephemeral_private,
        )
    )

    bob_ephemeral_public, bob_signature = (
        generate_signed_ephemeral_key(
            bob_identity,
            bob_ephemeral_private,
        )
    )

    alice_key = establish_authenticated_session_key(
        alice_ephemeral_private,
        bob_ephemeral_public,
        bob_identity.verify_key,
        bob_signature,
    )

    bob_key = establish_authenticated_session_key(
        bob_ephemeral_private,
        alice_ephemeral_public,
        alice_identity.verify_key,
        alice_signature,
    )

    assert alice_key == bob_key
    assert len(alice_key) == 32


def test_authenticated_exchange_rejects_wrong_peer():
    alice_identity = SigningKey.generate()
    bob_identity = SigningKey.generate()
    mallory_identity = SigningKey.generate()

    alice_private = generate_private_key()
    bob_private = generate_private_key()

    bob_public, bob_signature = generate_signed_ephemeral_key(
        bob_identity,
        bob_private,
    )

    with pytest.raises(
        ValueError,
        match="authentication failed",
    ):
        establish_authenticated_session_key(
            alice_private,
            bob_public,
            mallory_identity.verify_key,
            bob_signature,
        )


def test_context_is_versioned():
    assert KEX_CONTEXT == b"SecureChat authenticated session v1"


def test_signature_covers_ephemeral_public_key():
    identity = SigningKey.generate()
    private_key = generate_private_key()

    public_a, signature = generate_signed_ephemeral_key(
        identity,
        private_key,
    )

    public_b = public_key(generate_private_key())

    assert verify_signed_ephemeral_key(
        identity.verify_key,
        public_a,
        signature,
    )

    assert not verify_signed_ephemeral_key(
        identity.verify_key,
        public_b,
        signature,
    )
