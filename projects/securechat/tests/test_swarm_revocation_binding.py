import pytest

from securechat.swarm import MessagePiece
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.revocation_binding import (
    RevocationBinding,
    bind_revocation,
    verify_revocation_binding,
)
from securechat.swarm.rotation import SwarmRotation


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


def make_rotation():
    manifest = make_manifest()

    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    return SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )


def test_revocation_binding_creation():
    rotation = make_rotation()

    binding = RevocationBinding.create(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert binding.swarm_id == "swarm-1"
    assert binding.rotation_id == "rotation-1"
    assert binding.peer_id == "peer-7"
    assert binding.revoked_at == 1200
    assert binding.reason == "peer compromised"


def test_helper_creates_binding():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert isinstance(binding, RevocationBinding)
    assert binding.peer_id == "peer-7"


def test_unknown_peer_rejected():
    rotation = make_rotation()

    with pytest.raises(ValueError, match="not assigned"):
        RevocationBinding.create(
            rotation=rotation,
            peer_id="unknown-peer",
            revoked_at=1200,
            reason="peer compromised",
        )


def test_empty_peer_rejected():
    rotation = make_rotation()

    with pytest.raises(ValueError, match="peer_id"):
        RevocationBinding.create(
            rotation=rotation,
            peer_id="",
            revoked_at=1200,
            reason="peer compromised",
        )


def test_negative_revocation_time_rejected():
    rotation = make_rotation()

    with pytest.raises(ValueError, match="revoked_at"):
        RevocationBinding.create(
            rotation=rotation,
            peer_id="peer-7",
            revoked_at=-1,
            reason="peer compromised",
        )


def test_empty_reason_rejected():
    rotation = make_rotation()

    with pytest.raises(ValueError, match="reason"):
        RevocationBinding.create(
            rotation=rotation,
            peer_id="peer-7",
            revoked_at=1200,
            reason="",
        )


def test_canonical_bytes_are_deterministic():
    rotation = make_rotation()

    first = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    second = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert first.to_canonical_bytes() == second.to_canonical_bytes()


def test_binding_hash_is_deterministic():
    rotation = make_rotation()

    first = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    second = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert first.binding_hash() == second.binding_hash()


def test_binding_hash_is_sha256_length():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert len(binding.binding_hash()) == 64
    assert all(
        character in "0123456789abcdef"
        for character in binding.binding_hash()
    )


def test_binding_hash_verifies():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert binding.verify_hash(binding.binding_hash())


def test_wrong_binding_hash_rejected():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert not binding.verify_hash("0" * 64)


def test_matching_rotation_and_peer_verify():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert binding.verify(
        rotation=rotation,
        peer_id="peer-7",
    )


def test_helper_verification():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert verify_revocation_binding(
        binding,
        rotation=rotation,
        peer_id="peer-7",
    )


def test_wrong_peer_fails_verification():
    rotation = make_rotation()

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert not binding.verify(
        rotation=rotation,
        peer_id="peer-8",
    )


def test_wrong_rotation_fails_verification():
    manifest = make_manifest()

    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    first = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    second = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments=assignments,
        created_at=1500,
        expires_at=2000,
    )

    binding = bind_revocation(
        rotation=first,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert not binding.verify(
        rotation=second,
        peer_id="peer-7",
    )


def test_wrong_swarm_fails_verification():
    rotation = make_rotation()

    foreign_manifest = build_manifest(
        swarm_id="other-swarm",
        message_id="message-2",
        recipient_id="bob",
        pieces=tuple(
            MessagePiece.create(
                swarm_id="other-swarm",
                piece_index=index,
                ciphertext=bytes([index]) * 32,
            )
            for index in range(20)
        ),
        piece_size=32,
        expires_at=2000,
    )

    foreign_rotation = SwarmRotation.create(
        manifest=foreign_manifest,
        rotation_id="rotation-foreign",
        assignments={
            f"peer-{index}": (index,)
            for index in range(20)
        },
        created_at=1000,
        expires_at=1500,
    )

    binding = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert not binding.verify(
        rotation=foreign_rotation,
        peer_id="peer-7",
    )


def test_different_reason_changes_hash():
    rotation = make_rotation()

    first = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    second = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="policy violation",
    )

    assert first.binding_hash() != second.binding_hash()


def test_different_timestamp_changes_hash():
    rotation = make_rotation()

    first = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    second = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1201,
        reason="peer compromised",
    )

    assert first.binding_hash() != second.binding_hash()


def test_different_peer_changes_hash():
    rotation = make_rotation()

    first = bind_revocation(
        rotation=rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    second = bind_revocation(
        rotation=rotation,
        peer_id="peer-8",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert first.binding_hash() != second.binding_hash()


def test_different_rotation_changes_hash():
    manifest = make_manifest()

    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    first_rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    second_rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments=assignments,
        created_at=1500,
        expires_at=2000,
    )

    first = bind_revocation(
        rotation=first_rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    second = bind_revocation(
        rotation=second_rotation,
        peer_id="peer-7",
        revoked_at=1200,
        reason="peer compromised",
    )

    assert first.binding_hash() != second.binding_hash()
