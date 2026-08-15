import hashlib

import pytest

from securechat.swarm import AuthenticatedTransition
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.piece import MessagePiece
from securechat.swarm.rotation import SwarmRotation
from securechat.swarm.transition import SwarmTransition
from securechat.swarm.transition_auth import (
    sign_transition,
    verify_transition,
)


class FakeSigner:
    """Deterministic test signer; production code must use real crypto."""

    def __init__(self, secret: bytes):
        self.secret = secret

    def sign(self, data: bytes) -> bytes:
        return hashlib.sha256(self.secret + data).digest()


class FakeVerifier:
    """Verifier matching FakeSigner for protocol tests."""

    def __init__(self, secret: bytes):
        self.secret = secret

    def verify(self, data: bytes, signature: bytes) -> bool:
        expected = hashlib.sha256(self.secret + data).digest()
        return signature == expected


def make_manifest():
    pieces = tuple(
        MessagePiece.create(
            swarm_id="swarm-1",
            piece_index=index,
            ciphertext=bytes([index]) * 32,
        )
        for index in range(20)
    )

    return build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=32,
        expires_at=2000,
    )


def make_rotation(rotation_id, previous=None):
    manifest = make_manifest()

    return SwarmRotation.create(
        manifest=manifest,
        rotation_id=rotation_id,
        assignments={
            f"peer-{index}": (index,)
            for index in range(20)
        },
        created_at=1000 if previous is None else 1500,
        expires_at=1500 if previous is None else 2000,
        previous_rotation_id=(
            previous.rotation_id if previous is not None else None
        ),
    )


def make_transition():
    first = make_rotation("rotation-1")
    second = make_rotation("rotation-2", first)

    return SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )


def test_sign_transition():
    transition = make_transition()

    authenticated = sign_transition(
        transition=transition,
        signer_id="authority",
        signer=FakeSigner(b"secret"),
    )

    assert authenticated.signer_id == "authority"
    assert isinstance(authenticated.signature, bytes)
    assert authenticated.signature


def test_authenticated_transition_verifies():
    transition = make_transition()

    authenticated = sign_transition(
        transition=transition,
        signer_id="authority",
        signer=FakeSigner(b"secret"),
    )

    assert verify_transition(
        authenticated,
        FakeVerifier(b"secret"),
    )


def test_wrong_key_rejects_transition():
    transition = make_transition()

    authenticated = sign_transition(
        transition=transition,
        signer_id="authority",
        signer=FakeSigner(b"secret"),
    )

    assert not verify_transition(
        authenticated,
        FakeVerifier(b"wrong-secret"),
    )


def test_modified_transition_rejects_signature():
    transition = make_transition()

    authenticated = sign_transition(
        transition=transition,
        signer_id="authority",
        signer=FakeSigner(b"secret"),
    )

    modified = make_rotation("rotation-modified")

    modified_transition = SwarmTransition.create(
        previous_rotation=make_rotation("rotation-1"),
        next_rotation=modified,
        created_at=1500,
    )

    forged = AuthenticatedTransition(
        transition=modified_transition,
        signer_id=authenticated.signer_id,
        signature=authenticated.signature,
    )

    assert not forged.verify(FakeVerifier(b"secret"))

def test_signer_id_required():
    transition = make_transition()

    with pytest.raises(ValueError, match="signer_id"):
        sign_transition(
            transition=transition,
            signer_id="",
            signer=FakeSigner(b"secret"),
        )


def test_signer_must_return_bytes():
    class BadSigner:
        def sign(self, data):
            return "not-bytes"

    transition = make_transition()

    with pytest.raises(TypeError, match="bytes"):
        sign_transition(
            transition=transition,
            signer_id="authority",
            signer=BadSigner(),
        )


def test_signing_bytes_are_domain_separated():
    transition = make_transition()

    authenticated = AuthenticatedTransition(
        transition=transition,
        signer_id="authority",
        signature=b"signature",
    )

    assert authenticated.signing_bytes().startswith(
        b"securechat-swarm-transition-v1:"
    )


def test_transition_hash_does_not_depend_on_signature():
    transition = make_transition()

    first = AuthenticatedTransition(
        transition=transition,
        signer_id="authority",
        signature=b"signature-a",
    )

    second = AuthenticatedTransition(
        transition=transition,
        signer_id="authority",
        signature=b"signature-b",
    )

    assert first.transition_hash == second.transition_hash
    assert first.transition_hash == transition.transition_hash()


def test_invalid_verifier_result_is_false():
    transition = make_transition()

    authenticated = sign_transition(
        transition=transition,
        signer_id="authority",
        signer=FakeSigner(b"secret"),
    )

    class BrokenVerifier:
        def verify(self, data, signature):
            raise RuntimeError("verification failure")

    assert authenticated.verify(BrokenVerifier()) is False
