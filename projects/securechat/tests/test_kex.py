"""Tests for SecureChat ephemeral X25519 key agreement."""

import pytest

from securechat.kex import (
    PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE,
    SESSION_KEY_SIZE,
    SHARED_SECRET_SIZE,
    derive_session_key,
    derive_shared_secret,
    establish_session_key,
    generate_private_key,
    public_key,
)


def test_private_key_generation():
    key = generate_private_key()

    assert isinstance(key, bytes)
    assert len(key) == PRIVATE_KEY_SIZE


def test_public_key_generation():
    private_key = generate_private_key()
    public = public_key(private_key)

    assert isinstance(public, bytes)
    assert len(public) == PUBLIC_KEY_SIZE


def test_two_peers_derive_same_shared_secret():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key(alice_private)
    bob_public = public_key(bob_private)

    alice_secret = derive_shared_secret(
        alice_private,
        bob_public,
    )
    bob_secret = derive_shared_secret(
        bob_private,
        alice_public,
    )

    assert len(alice_secret) == SHARED_SECRET_SIZE
    assert alice_secret == bob_secret


def test_shared_secret_is_not_public_key():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key(alice_private)
    bob_public = public_key(bob_private)

    shared = derive_shared_secret(
        alice_private,
        bob_public,
    )

    assert shared != alice_public
    assert shared != bob_public


def test_session_keys_match():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key(alice_private)
    bob_public = public_key(bob_private)

    alice_key = establish_session_key(
        alice_private,
        bob_public,
    )
    bob_key = establish_session_key(
        bob_private,
        alice_public,
    )

    assert len(alice_key) == SESSION_KEY_SIZE
    assert alice_key == bob_key


def test_fresh_ephemeral_keys_produce_different_session_keys():
    bob_private = generate_private_key()
    bob_public = public_key(bob_private)

    alice_private_a = generate_private_key()
    alice_private_b = generate_private_key()

    key_a = establish_session_key(
        alice_private_a,
        bob_public,
    )
    key_b = establish_session_key(
        alice_private_b,
        bob_public,
    )

    assert key_a != key_b


def test_context_separates_session_keys():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key(alice_private)
    bob_public = public_key(bob_private)

    key_a = establish_session_key(
        alice_private,
        bob_public,
        context=b"SecureChat session v1",
    )
    key_b = establish_session_key(
        bob_private,
        alice_public,
        context=b"SecureChat other context",
    )

    assert key_a != key_b


def test_invalid_private_key_length():
    with pytest.raises(ValueError):
        public_key(b"short")


def test_invalid_peer_public_key_length():
    private_key = generate_private_key()

    with pytest.raises(ValueError):
        derive_shared_secret(
            private_key,
            b"short",
        )


def test_invalid_shared_secret_length():
    with pytest.raises(ValueError):
        derive_session_key(b"short")


def test_invalid_private_key_type():
    with pytest.raises(TypeError):
        public_key("not-bytes")


def test_invalid_public_key_type():
    private_key = generate_private_key()

    with pytest.raises(TypeError):
        derive_shared_secret(
            private_key,
            "not-bytes",
        )


def test_invalid_context_type():
    with pytest.raises(TypeError):
        derive_session_key(
            generate_private_key(),
            context="not-bytes",
        )


def test_complete_two_peer_exchange():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key(alice_private)
    bob_public = public_key(bob_private)

    alice_session_key = establish_session_key(
        alice_private,
        bob_public,
    )
    bob_session_key = establish_session_key(
        bob_private,
        alice_public,
    )

    assert alice_session_key == bob_session_key
    assert len(alice_session_key) == SESSION_KEY_SIZE


def test_session_key_is_not_shared_secret():
    alice_private = generate_private_key()
    bob_private = generate_private_key()

    alice_public = public_key(alice_private)
    bob_public = public_key(bob_private)

    shared_secret = derive_shared_secret(
        alice_private,
        bob_public,
    )
    session_key = establish_session_key(
        alice_private,
        bob_public,
    )

    assert session_key != shared_secret
    assert len(session_key) == SESSION_KEY_SIZE
