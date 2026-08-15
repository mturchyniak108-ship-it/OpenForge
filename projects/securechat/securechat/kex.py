"""SecureChat ephemeral X25519 key agreement.

This module provides ephemeral Diffie-Hellman key agreement and
HKDF-SHA256 session-key derivation.

It does not perform authentication by itself. Peer identity
authentication must be provided by the identity/peer layers.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from nacl.bindings import (
    crypto_scalarmult,
    crypto_scalarmult_base,
)

PRIVATE_KEY_SIZE = 32
PUBLIC_KEY_SIZE = 32
SHARED_SECRET_SIZE = 32
SESSION_KEY_SIZE = 32


def generate_private_key() -> bytes:
    """Generate a fresh 256-bit ephemeral X25519 private key."""
    return os.urandom(PRIVATE_KEY_SIZE)


def public_key(private_key: bytes) -> bytes:
    """Derive the X25519 public key for a private key."""
    _require_size(
        private_key,
        PRIVATE_KEY_SIZE,
        "private_key",
    )

    return crypto_scalarmult_base(private_key)


def derive_shared_secret(
    private_key: bytes,
    peer_public_key: bytes,
) -> bytes:
    """Perform X25519 Diffie-Hellman key agreement."""
    _require_size(
        private_key,
        PRIVATE_KEY_SIZE,
        "private_key",
    )
    _require_size(
        peer_public_key,
        PUBLIC_KEY_SIZE,
        "peer_public_key",
    )

    return crypto_scalarmult(
        private_key,
        peer_public_key,
    )


def derive_session_key(
    shared_secret: bytes,
    *,
    context: bytes = b"SecureChat session v1",
) -> bytes:
    """Derive a 256-bit session key using HKDF-SHA256.

    The shared secret is never used directly as the encryption key.
    """
    _require_size(
        shared_secret,
        SHARED_SECRET_SIZE,
        "shared_secret",
    )

    if not isinstance(context, bytes):
        raise TypeError("context must be bytes")

    # HKDF-Extract with an all-zero salt.
    salt = bytes(hashlib.sha256().digest_size)
    pseudorandom_key = hmac.new(
        salt,
        shared_secret,
        hashlib.sha256,
    ).digest()

    # HKDF-Expand for exactly one 32-byte block.
    info = context
    block = hmac.new(
        pseudorandom_key,
        info + b"\x01",
        hashlib.sha256,
    ).digest()

    return block[:SESSION_KEY_SIZE]


def establish_session_key(
    private_key: bytes,
    peer_public_key: bytes,
    *,
    context: bytes = b"SecureChat session v1",
) -> bytes:
    """Perform X25519 agreement and derive the session encryption key."""
    shared_secret = derive_shared_secret(
        private_key,
        peer_public_key,
    )

    return derive_session_key(
        shared_secret,
        context=context,
    )


def _require_size(
    value: bytes,
    expected: int,
    name: str,
) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")

    if len(value) != expected:
        raise ValueError(
            f"{name} must be exactly {expected} bytes"
        )
