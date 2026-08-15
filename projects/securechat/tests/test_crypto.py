"""Tests for the SecureChat cryptographic foundation."""

import pytest

from nacl.exceptions import CryptoError

from securechat.crypto import KEY_SIZE, decrypt, encrypt, generate_key


def test_key_generation():
    key = generate_key()

    assert isinstance(key, bytes)
    assert len(key) == KEY_SIZE


def test_encrypt_decrypt_round_trip():
    key = generate_key()
    plaintext = b"SecureChat Android test message"

    ciphertext = encrypt(key, plaintext)
    recovered = decrypt(key, ciphertext)

    assert ciphertext != plaintext
    assert recovered == plaintext


def test_encryption_produces_different_ciphertexts():
    key = generate_key()
    plaintext = b"same message"

    ciphertext_a = encrypt(key, plaintext)
    ciphertext_b = encrypt(key, plaintext)

    assert ciphertext_a != ciphertext_b
    assert decrypt(key, ciphertext_a) == plaintext
    assert decrypt(key, ciphertext_b) == plaintext


def test_tampering_is_detected():
    key = generate_key()
    ciphertext = bytearray(encrypt(key, b"authenticated message"))

    ciphertext[-1] ^= 0x01

    with pytest.raises(CryptoError):
        decrypt(key, bytes(ciphertext))


def test_wrong_key_is_rejected():
    key_a = generate_key()
    key_b = generate_key()

    ciphertext = encrypt(key_a, b"secret")

    with pytest.raises(CryptoError):
        decrypt(key_b, ciphertext)


def test_invalid_key_length_is_rejected():
    with pytest.raises(ValueError):
        encrypt(b"too-short", b"message")

    with pytest.raises(ValueError):
        decrypt(b"too-short", b"ciphertext")
