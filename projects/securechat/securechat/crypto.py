"""SecureChat authenticated encryption.

Uses PyNaCl's SecretBox implementation, backed by libsodium.
No custom cryptography is implemented here.
"""

from __future__ import annotations

from nacl.secret import SecretBox
from nacl.utils import random


KEY_SIZE = SecretBox.KEY_SIZE


def generate_key() -> bytes:
    """Generate a new 256-bit encryption key."""
    return random(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt and authenticate plaintext.

    The returned value contains the nonce and authenticated ciphertext.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be exactly {KEY_SIZE} bytes")

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    return SecretBox(key).encrypt(plaintext)


def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate ciphertext.

    Raises nacl.exceptions.CryptoError if authentication fails.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be exactly {KEY_SIZE} bytes")

    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")

    return SecretBox(key).decrypt(ciphertext)
