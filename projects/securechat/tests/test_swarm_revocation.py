import pytest

from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.piece import MessagePiece
from securechat.swarm.rotation import SwarmRotation
from securechat.swarm.transition import SwarmTransition
from securechat.swarm.revocation import (
    PurgeAuthorization,
    create_purge_authorizations,
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


def make_rotation(rotation_id, assignments, created_at, expires_at, previous=None):
    manifest = make_manifest()

    return SwarmRotation.create(
        manifest=manifest,
        rotation_id=rotation_id,
        assignments=assignments,
        created_at=created_at,
        expires_at=expires_at,
        previous_rotation_id=(
            previous.rotation_id if previous else None
        ),
    )


def test_purge_authorization_creation():
    authorization = PurgeAuthorization(
        swarm_id="swarm-1",
        peer_id="peer-1",
        rotation_id="rotation-2",
        revoked_piece_indices=(1, 2),
        created_at=1500,
    )

    assert authorization.peer_id == "peer-1"
    assert authorization.revoked_piece_indices == (1, 2)
    assert authorization.has_pieces_to_purge is True


def test_empty_purge_has_no_pieces():
    authorization = PurgeAuthorization(
        swarm_id="swarm-1",
        peer_id="peer-1",
        rotation_id="rotation-2",
        revoked_piece_indices=(),
        created_at=1500,
    )

    assert authorization.has_pieces_to_purge is False


def test_negative_piece_rejected():
    with pytest.raises(ValueError, match="negative"):
        PurgeAuthorization(
            swarm_id="swarm-1",
            peer_id="peer-1",
            rotation_id="rotation-2",
            revoked_piece_indices=(-1,),
            created_at=1500,
        )


def test_duplicate_piece_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        PurgeAuthorization(
            swarm_id="swarm-1",
            peer_id="peer-1",
            rotation_id="rotation-2",
            revoked_piece_indices=(1, 1),
            created_at=1500,
        )


def test_rotation_movement_creates_purge_authorization():
    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    first = make_rotation(
        "rotation-1",
        assignments,
        1000,
        1500,
    )

    moved = dict(assignments)
    moved["peer-0"] = (1,)
    moved["peer-1"] = (0,)

    # Rebuild a complete one-piece-per-peer assignment.
    moved = {
        "peer-0": (1,),
        "peer-1": (0,),
        **{
            f"peer-{index}": (index,)
            for index in range(2, 20)
        },
    }

    second = make_rotation(
        "rotation-2",
        moved,
        1500,
        2000,
        first,
    )

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    authorizations = create_purge_authorizations(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
        created_at=1500,
    )

    by_peer = {
        item.peer_id: item
        for item in authorizations
    }

    assert by_peer["peer-0"].revoked_piece_indices == (0,)
    assert by_peer["peer-1"].revoked_piece_indices == (1,)


def test_unchanged_rotation_creates_no_purge():
    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    first = make_rotation(
        "rotation-1",
        assignments,
        1000,
        1500,
    )

    second = make_rotation(
        "rotation-2",
        assignments,
        1500,
        2000,
        first,
    )

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=second,
        created_at=1500,
    )

    authorizations = create_purge_authorizations(
        previous_rotation=first,
        next_rotation=second,
        transition=transition,
        created_at=1500,
    )

    assert authorizations == ()


def test_wrong_transition_is_rejected():
    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    first = make_rotation(
        "rotation-1",
        assignments,
        1000,
        1500,
    )

    second = make_rotation(
        "rotation-2",
        assignments,
        1500,
        2000,
        first,
    )

    other = make_rotation(
        "rotation-3",
        assignments,
        1500,
        2000,
        first,
    )

    transition = SwarmTransition.create(
        previous_rotation=first,
        next_rotation=other,
        created_at=1500,
    )

    with pytest.raises(ValueError, match="transition"):
        create_purge_authorizations(
            previous_rotation=first,
            next_rotation=second,
            transition=transition,
            created_at=1500,
        )
