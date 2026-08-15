import pytest

from securechat.swarm import MessagePiece
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.rotation import SwarmRotation
from securechat.swarm.transition import SwarmTransition


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


def assignments_a():
    return {
        f"peer-{index}": (index,)
        for index in range(20)
    }


def assignments_b():
    result = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    del result["peer-0"]
    result["peer-new"] = (0,)

    return result


def make_rotations():
    manifest = make_manifest()

    first = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments_a(),
        created_at=1000,
        expires_at=2000,
    )

    second = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments=assignments_b(),
        created_at=1500,
        expires_at=2500,
        previous_rotation_id="rotation-1",
    )

    return first, second


def test_transition_creation():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    assert transition.swarm_id == "swarm-1"
    assert transition.previous_rotation_id == "rotation-1"
    assert transition.next_rotation_id == "rotation-2"


def test_revoked_peer_detected():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    assert transition.revoked_peers == ("peer-0",)


def test_granted_peer_detected():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    assert transition.granted_peers == ("peer-new",)


def test_moved_piece_detected():
    first, second = make_rotations()

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    assert transition.moved_pieces == (
        (0, "peer-0", "peer-new"),
    )


def test_transition_hash_is_deterministic():
    first, second = make_rotations()

    a = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    b = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    assert a.transition_hash() == b.transition_hash()


def test_different_swarms_rejected():
    first, second = make_rotations()

    second = SwarmRotation(
        swarm_id="other-swarm",
        rotation_id=second.rotation_id,
        previous_rotation_id=second.previous_rotation_id,
        assignments=second.assignments,
        created_at=second.created_at,
        expires_at=second.expires_at,
    )

    with pytest.raises(ValueError, match="different swarms"):
        SwarmTransition.create(
            previous_rotation=first,
            next_rotation=second,
            created_at=1500,
        )


def test_broken_chain_rejected():
    first, second = make_rotations()

    second = SwarmRotation(
        swarm_id=second.swarm_id,
        rotation_id=second.rotation_id,
        previous_rotation_id="wrong-rotation",
        assignments=second.assignments,
        created_at=second.created_at,
        expires_at=second.expires_at,
    )

    with pytest.raises(ValueError, match="does not reference"):
        SwarmTransition.create(
            previous_rotation=first,
            next_rotation=second,
            created_at=1500,
        )
