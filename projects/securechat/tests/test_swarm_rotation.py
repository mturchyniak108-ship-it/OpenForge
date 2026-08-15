import pytest

from securechat.swarm import MessagePiece
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.rotation import SwarmRotation, rotate


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


def make_assignments():
    return {
        f"peer-{index}": (index,)
        for index in range(20)
    }


def test_rotation_creation():
    manifest = make_manifest()

    rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=make_assignments(),
        created_at=1000,
        expires_at=1500,
    )

    assert rotation.swarm_id == "swarm-1"
    assert rotation.rotation_id == "rotation-1"
    assert rotation.previous_rotation_id is None
    assert len(rotation.assignments) == 20


def test_rotation_assigns_every_piece_exactly_once():
    manifest = make_manifest()

    rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=make_assignments(),
        created_at=1000,
        expires_at=1500,
    )

    owners = [
        rotation.piece_owner(index)
        for index in range(manifest.piece_count)
    ]

    assert len(owners) == 20
    assert len(set(owners)) == 20


def test_five_percent_limit_is_enforced():
    manifest = make_manifest()

    assignments = make_assignments()
    assignments["peer-0"] = (0, 1)

    with pytest.raises(ValueError, match="5%"):
        SwarmRotation.create(
            manifest=manifest,
            rotation_id="rotation-1",
            assignments=assignments,
            created_at=1000,
            expires_at=1500,
        )


def test_duplicate_piece_assignment_rejected():
    manifest = make_manifest()

    assignments = make_assignments()
    assignments["peer-1"] = (0, 1)

    with pytest.raises(ValueError, match="more than one"):
        SwarmRotation.create(
            manifest=manifest,
            rotation_id="rotation-1",
            assignments=assignments,
            created_at=1000,
            expires_at=1500,
        )


def test_missing_piece_rejected():
    manifest = make_manifest()

    assignments = make_assignments()
    del assignments["peer-19"]

    with pytest.raises(ValueError, match="missing"):
        SwarmRotation.create(
            manifest=manifest,
            rotation_id="rotation-1",
            assignments=assignments,
            created_at=1000,
            expires_at=1500,
        )


def test_rotation_chain():
    manifest = make_manifest()
    assignments = make_assignments()

    first = rotate(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    second = rotate(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments=assignments,
        created_at=1499,
        expires_at=2000,
        previous_rotation=first,
    )

    assert second.previous_rotation_id == "rotation-1"


def test_expired_rotation():
    manifest = make_manifest()

    rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=make_assignments(),
        created_at=1000,
        expires_at=1500,
    )

    assert rotation.is_expired(1499) is False
    assert rotation.is_expired(1500) is True


def test_previous_expired_rotation_cannot_be_rotated():
    manifest = make_manifest()
    assignments = make_assignments()

    first = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    with pytest.raises(ValueError, match="already expired"):
        rotate(
            manifest=manifest,
            rotation_id="rotation-2",
            assignments=assignments,
            created_at=1500,
            expires_at=2000,
            previous_rotation=first,
        )


def test_peer_lease_matches_rotation():
    manifest = make_manifest()

    rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=make_assignments(),
        created_at=1000,
        expires_at=1500,
    )

    lease = rotation.lease_for_peer("peer-7")

    assert lease.peer_id == "peer-7"
    assert lease.piece_indices == (7,)
    assert lease.allocation_limit == 0.05


def test_unknown_peer_has_no_lease():
    manifest = make_manifest()

    rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=make_assignments(),
        created_at=1000,
        expires_at=1500,
    )

    with pytest.raises(KeyError):
        rotation.lease_for_peer("unknown-peer")


def test_rotation_hash_is_deterministic():
    manifest = make_manifest()
    assignments = make_assignments()

    first = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    second = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    assert first.rotation_hash() == second.rotation_hash()


def test_small_swarm_rejected_by_five_percent_policy():
    pieces = tuple(
        MessagePiece.create(
            swarm_id="small",
            piece_index=index,
            ciphertext=b"x" * 32,
        )
        for index in range(19)
    )

    manifest = build_manifest(
        swarm_id="small",
        message_id="message",
        recipient_id="bob",
        pieces=pieces,
        piece_size=32,
        expires_at=2000,
    )

    assignments = {
        f"peer-{index}": (index,)
        for index in range(19)
    }

    with pytest.raises(ValueError, match="at least 20"):
        SwarmRotation.create(
            manifest=manifest,
            rotation_id="rotation-1",
            assignments=assignments,
            created_at=1000,
            expires_at=1500,
        )
