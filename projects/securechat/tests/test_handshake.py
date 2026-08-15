import os

import pytest
from nacl.signing import SigningKey

from securechat.handshake import (
    HANDSHAKE_VERSION,
    HandshakeMessage,
    HandshakeRole,
    create_handshake,
    verify_handshake,
)
from securechat.identity import Identity


def make_identity():
    return Identity.create("Alice")


def test_handshake_creation():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, private_key = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    assert message.version == HANDSHAKE_VERSION
    assert message.role == HandshakeRole.INITIATOR
    assert message.identity_id == identity.identity_id
    assert len(message.ephemeral_public_key) == 32
    assert len(message.signature) == 64
    assert len(message.nonce) == 32
    assert len(private_key) == 32


def test_handshake_verification():
    identity = make_identity()
    signing_key = SigningKey.generate()
    nonce = os.urandom(32)

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=nonce,
    )

    assert verify_handshake(
        message,
        identity,
        signing_key.verify_key,
        expected_role=HandshakeRole.INITIATOR,
        expected_nonce=nonce,
    )


def test_handshake_round_trip_serialization():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.RESPONDER,
        nonce=os.urandom(32),
    )

    restored = HandshakeMessage.from_bytes(message.to_bytes())

    assert restored == message


def test_tampered_identity_is_rejected():
    identity = make_identity()
    other = Identity.create("Mallory")
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    assert not verify_handshake(
        message,
        other,
        signing_key.verify_key,
    )


def test_tampered_signature_is_rejected():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    tampered = HandshakeMessage(
        version=message.version,
        role=message.role,
        identity_id=message.identity_id,
        ephemeral_public_key=message.ephemeral_public_key,
        signature=bytes(
            byte ^ 1 for byte in message.signature
        ),
        nonce=message.nonce,
    )

    assert not verify_handshake(
        tampered,
        identity,
        signing_key.verify_key,
    )


def test_tampered_ephemeral_key_is_rejected():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    changed_key = bytearray(message.ephemeral_public_key)
    changed_key[0] ^= 1

    tampered = HandshakeMessage(
        version=message.version,
        role=message.role,
        identity_id=message.identity_id,
        ephemeral_public_key=bytes(changed_key),
        signature=message.signature,
        nonce=message.nonce,
    )

    assert not verify_handshake(
        tampered,
        identity,
        signing_key.verify_key,
    )


def test_wrong_role_is_rejected():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    assert not verify_handshake(
        message,
        identity,
        signing_key.verify_key,
        expected_role=HandshakeRole.RESPONDER,
    )


def test_wrong_nonce_is_rejected():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    assert not verify_handshake(
        message,
        identity,
        signing_key.verify_key,
        expected_nonce=os.urandom(32),
    )


def test_wrong_version_is_rejected():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    tampered = HandshakeMessage(
        version=HANDSHAKE_VERSION + 1,
        role=message.role,
        identity_id=message.identity_id,
        ephemeral_public_key=message.ephemeral_public_key,
        signature=message.signature,
        nonce=message.nonce,
    )

    assert not verify_handshake(
        tampered,
        identity,
        signing_key.verify_key,
    )


def test_malformed_wire_data_is_rejected():
    with pytest.raises(ValueError):
        HandshakeMessage.from_bytes(b"not a handshake")


def test_missing_field_is_rejected():
    data = (
        b'{"version":1,"role":"initiator",'
        b'"identity_id":"abc"}'
    )

    with pytest.raises(ValueError, match="missing"):
        HandshakeMessage.from_bytes(data)


def test_invalid_nonce_length_is_rejected():
    identity = make_identity()
    signing_key = SigningKey.generate()

    with pytest.raises(ValueError, match="nonce"):
        create_handshake(
            identity,
            signing_key,
            role=HandshakeRole.INITIATOR,
            nonce=b"short",
        )


def test_identity_signature_is_bound_to_nonce():
    identity = make_identity()
    signing_key = SigningKey.generate()

    message, _ = create_handshake(
        identity,
        signing_key,
        role=HandshakeRole.INITIATOR,
        nonce=os.urandom(32),
    )

    changed_nonce = os.urandom(32)

    tampered = HandshakeMessage(
        version=message.version,
        role=message.role,
        identity_id=message.identity_id,
        ephemeral_public_key=message.ephemeral_public_key,
        signature=message.signature,
        nonce=changed_nonce,
    )

    assert not verify_handshake(
        tampered,
        identity,
        signing_key.verify_key,
    )
