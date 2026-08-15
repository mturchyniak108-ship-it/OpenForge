import pytest

from securechat.swarm import MessagePiece
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.rotation import SwarmRotation
from securechat.swarm.rotation_binding import (
    RotationBinding,
    bind_rotation,
    verify_rotation_binding,
)


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


def make_rotation(
    *,
    rotation_id="rotation-1",
    created_at=1000,
    expires_at=1500,
):
    manifest = make_manifest()

    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    return SwarmRotation.create(
        manifest=manifest,
        rotation_id=rotation_id,
        assignments=assignments,
        created_at=created_at,
        expires_at=expires_at,
    )


def test_rotation_binding_creation():
    rotation = make_rotation()

    binding = RotationBinding.create(rotation=rotation)

    assert binding.swarm_id == "swarm-1"
    assert binding.rotation_id == "rotation-1"
    assert binding.rotation_hash == rotation.rotation_hash()
    assert binding.created_at == 1000
    assert binding.expires_at == 1500


def test_helper_creates_binding():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert isinstance(binding, RotationBinding)
    assert binding.rotation_id == rotation.rotation_id


def test_canonical_bytes_are_deterministic():
    rotation = make_rotation()

    first = bind_rotation(rotation=rotation)
    second = bind_rotation(rotation=rotation)

    assert first.to_canonical_bytes() == second.to_canonical_bytes()


def test_binding_hash_is_deterministic():
    rotation = make_rotation()

    first = bind_rotation(rotation=rotation)
    second = bind_rotation(rotation=rotation)

    assert first.binding_hash() == second.binding_hash()


def test_binding_hash_is_sha256_length():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert len(binding.binding_hash()) == 64
    assert all(
        character in "0123456789abcdef"
        for character in binding.binding_hash()
    )


def test_binding_hash_verifies():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert binding.verify_hash(binding.binding_hash())


def test_wrong_binding_hash_rejected():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert not binding.verify_hash("0" * 64)


def test_matching_rotation_verifies():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert binding.verify(rotation=rotation)


def test_helper_verification():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert verify_rotation_binding(
        binding,
        rotation=rotation,
    )


def test_different_rotation_id_fails():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)
    other_rotation = make_rotation(rotation_id="rotation-2")

    assert not binding.verify(rotation=other_rotation)


def test_different_creation_time_fails():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)
    other_rotation = make_rotation(created_at=1001)

    assert not binding.verify(rotation=other_rotation)


def test_different_expiry_time_fails():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)
    other_rotation = make_rotation(expires_at=1600)

    assert not binding.verify(rotation=other_rotation)


def test_different_rotation_assignments_fail():
    rotation = make_rotation()

    manifest = make_manifest()

    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    assignments["peer-7"] = (7,)
    assignments["peer-8"] = (8,)

    other_rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    binding = bind_rotation(rotation=rotation)

    assert binding.verify(rotation=other_rotation)


def test_different_rotation_hash_is_detected():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    tampered = RotationBinding(
        swarm_id=binding.swarm_id,
        rotation_id=binding.rotation_id,
        rotation_hash="0" * 64,
        created_at=binding.created_at,
        expires_at=binding.expires_at,
    )

    assert not tampered.verify(rotation=rotation)


def test_different_swarm_fails():
    rotation = make_rotation()

    foreign_pieces = tuple(
        MessagePiece.create(
            swarm_id="other-swarm",
            piece_index=index,
            ciphertext=bytes([index]) * 32,
        )
        for index in range(20)
    )

    foreign_manifest = build_manifest(
        swarm_id="other-swarm",
        message_id="message-2",
        recipient_id="bob",
        pieces=foreign_pieces,
        piece_size=32,
        expires_at=2000,
    )

    foreign_rotation = SwarmRotation.create(
        manifest=foreign_manifest,
        rotation_id="rotation-1",
        assignments={
            f"peer-{index}": (index,)
            for index in range(20)
        },
        created_at=1000,
        expires_at=1500,
    )

    binding = bind_rotation(rotation=rotation)

    assert not binding.verify(rotation=foreign_rotation)


def test_different_rotation_changes_binding_hash():
    first_rotation = make_rotation(rotation_id="rotation-1")
    second_rotation = make_rotation(rotation_id="rotation-2")

    first = bind_rotation(rotation=first_rotation)
    second = bind_rotation(rotation=second_rotation)

    assert first.binding_hash() != second.binding_hash()


def test_different_expiry_changes_binding_hash():
    first_rotation = make_rotation(expires_at=1500)
    second_rotation = make_rotation(expires_at=1600)

    first = bind_rotation(rotation=first_rotation)
    second = bind_rotation(rotation=second_rotation)

    assert first.binding_hash() != second.binding_hash()


def test_binding_hash_changes_when_binding_metadata_changes():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    modified = RotationBinding(
        swarm_id=binding.swarm_id,
        rotation_id=binding.rotation_id,
        rotation_hash=binding.rotation_hash,
        created_at=binding.created_at + 1,
        expires_at=binding.expires_at,
    )

    assert modified.binding_hash() != binding.binding_hash()


def test_empty_expected_hash_is_rejected():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert not binding.verify_hash("")


def test_non_string_expected_hash_is_rejected():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert not binding.verify_hash(None)


def test_binding_contains_rotation_hash():
    rotation = make_rotation()

    binding = bind_rotation(rotation=rotation)

    assert binding.rotation_hash == rotation.rotation_hash()
