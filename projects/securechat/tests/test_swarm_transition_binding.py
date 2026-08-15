import pytest

from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.piece import MessagePiece
from securechat.swarm.rotation import SwarmRotation
from securechat.swarm.transition import SwarmTransition
from securechat.swarm.transition_binding import (
    TransitionBinding,
    bind_transition,
    verify_transition_binding,
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
        expires_at=3000,
    )


def make_rotations():
    manifest = make_manifest()

    first = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments={
            f"peer-{index}": (index,)
            for index in range(20)
        },
        created_at=1000,
        expires_at=2000,
    )

    second = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments={
            f"peer-{index}": (index,)
            for index in range(20)
        },
        created_at=1500,
        expires_at=2500,
        previous_rotation_id="rotation-1",
    )

    return first, second


def make_transition():
    first, second = make_rotations()

    return (
        first,
        second,
        SwarmTransition.create(
            previous_rotation=first,
            next_rotation=second,
            created_at=1500,
        ),
    )


def test_transition_binding_creation():
    first, second, transition = make_transition()

    binding = bind_transition(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    assert binding.swarm_id == "swarm-1"
    assert binding.previous_rotation_id == "rotation-1"
    assert binding.next_rotation_id == "rotation-2"
    assert binding.transition_hash == transition.transition_hash()


def test_transition_binding_hash_is_deterministic():
    first, second, transition = make_transition()

    a = TransitionBinding.create(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    b = TransitionBinding.create(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    assert a.binding_hash() == b.binding_hash()


def test_transition_binding_verifies():
    first, second, transition = make_transition()

    binding = bind_transition(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    assert verify_transition_binding(
        binding,
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )


def test_modified_transition_rejected():
    first, second, transition = make_transition()

    binding = bind_transition(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    modified = SwarmTransition(
        swarm_id=transition.swarm_id,
        previous_rotation_id=transition.previous_rotation_id,
        next_rotation_id=transition.next_rotation_id,
        revoked_peers=transition.revoked_peers,
        granted_peers=transition.granted_peers,
        moved_pieces=transition.moved_pieces,
        created_at=transition.created_at + 1,
    )

    assert not binding.verify(
        previous_rotation=first,
        next_rotation=second,
        transition=modified,
    )


def test_modified_next_rotation_rejected():
    first, second, transition = make_transition()

    binding = bind_transition(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    modified = SwarmRotation(
        swarm_id=second.swarm_id,
        rotation_id=second.rotation_id,
        previous_rotation_id=second.previous_rotation_id,
        assignments=second.assignments,
        created_at=second.created_at,
        expires_at=second.expires_at + 1,
    )

    assert not binding.verify(
        previous_rotation=first,
        next_rotation=modified,
        transition=transition,
    )


def test_different_swarm_rejected():
    first, second, transition = make_transition()

    other = SwarmRotation(
        swarm_id="other-swarm",
        rotation_id=second.rotation_id,
        previous_rotation_id=second.previous_rotation_id,
        assignments=second.assignments,
        created_at=second.created_at,
        expires_at=second.expires_at,
    )

    with pytest.raises(ValueError, match="swarm"):
        TransitionBinding.create(
            previous_rotation=first,
            next_rotation=other,
            transition=transition,
        )


def test_mismatched_transition_rejected():
    first, second, transition = make_transition()

    other_first = SwarmRotation(
        swarm_id=first.swarm_id,
        rotation_id="other-rotation",
        previous_rotation_id=None,
        assignments=first.assignments,
        created_at=first.created_at,
        expires_at=first.expires_at,
    )

    with pytest.raises(ValueError, match="previous_rotation_id"):
        TransitionBinding.create(
            previous_rotation=other_first,
            next_rotation=second,
            transition=transition,
        )


def test_verify_hash():
    first, second, transition = make_transition()

    binding = bind_transition(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    assert binding.verify_hash(binding.binding_hash())
    assert not binding.verify_hash("wrong-hash")
    assert not binding.verify_hash(None)


def test_binding_is_immutable():
    first, second, transition = make_transition()

    binding = bind_transition(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
    )

    with pytest.raises(AttributeError):
        binding.swarm_id = "modified"
