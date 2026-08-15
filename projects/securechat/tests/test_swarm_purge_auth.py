import pytest

from securechat.swarm.purge_auth import (
    PurgeAuthorization,
    create_purge_authorization,
    verify_purge_authorization,
    verify_purge_record,
)


class FakeTransition:
    swarm_id = "swarm-1"
    next_rotation_id = "rotation-2"
    transition_hash = "transition-hash"
    created_at = 1000
    expires_at = 2000
    authorized_peers = ("peer-1", "peer-2")
    peer_piece_indices = {
        "peer-1": (0, 1),
        "peer-2": (2, 3),
    }


def make_authorization(**overrides):
    values = {
        "swarm_id": "swarm-1",
        "rotation_id": "rotation-2",
        "peer_id": "peer-1",
        "piece_indices": (0, 1),
        "transition_hash": "transition-hash",
        "timestamp": 1500,
        "signature": b"signature",
    }
    values.update(overrides)
    return PurgeAuthorization(**values)


def test_purge_authorization_creation():
    authorization = make_authorization()

    assert authorization.swarm_id == "swarm-1"
    assert authorization.rotation_id == "rotation-2"
    assert authorization.peer_id == "peer-1"
    assert authorization.piece_indices == (0, 1)


def test_purge_authorization_canonical_hash_is_deterministic():
    first = make_authorization()
    second = make_authorization()

    assert first.to_canonical_bytes() == second.to_canonical_bytes()
    assert first.authorization_hash() == second.authorization_hash()


def test_authorization_requires_nonnegative_piece_indices():
    with pytest.raises(ValueError, match="negative"):
        make_authorization(piece_indices=(-1,))


def test_authorization_rejects_duplicate_piece_indices():
    with pytest.raises(ValueError, match="duplicates"):
        make_authorization(piece_indices=(0, 0))


def test_authorized_peer_can_purge_assigned_pieces():
    authorization = make_authorization()

    assert verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_wrong_swarm_is_rejected():
    authorization = make_authorization(swarm_id="other-swarm")

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_wrong_transition_hash_is_rejected():
    authorization = make_authorization(
        transition_hash="wrong-transition",
    )

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_wrong_rotation_is_rejected():
    authorization = make_authorization(
        rotation_id="old-rotation",
    )

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_unknown_peer_is_rejected():
    authorization = make_authorization(peer_id="unknown")

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_unassigned_piece_is_rejected():
    authorization = make_authorization(piece_indices=(0, 2))

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_authorization_before_transition_is_rejected():
    authorization = make_authorization(timestamp=999)

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_authorization_at_expiry_is_rejected():
    authorization = make_authorization(timestamp=2000)

    assert not verify_purge_authorization(
        authorization,
        transition=FakeTransition(),
    )


def test_purge_record_can_be_verified():
    authorization = make_authorization()
    record = authorization.to_purge_record()

    assert verify_purge_record(
        authorization,
        record,
        transition=FakeTransition(),
    )


def test_tampered_purge_record_is_rejected():
    authorization = make_authorization()
    record = authorization.to_purge_record()

    tampered = type(record)(
        swarm_id=record.swarm_id,
        peer_id=record.peer_id,
        receipt_hash="tampered",
        timestamp=record.timestamp,
        deleted=True,
    )

    assert not verify_purge_record(
        authorization,
        tampered,
        transition=FakeTransition(),
    )


def test_undeleted_purge_record_is_rejected():
    authorization = make_authorization()

    record = type(authorization.to_purge_record())(
        swarm_id="swarm-1",
        peer_id="peer-1",
        receipt_hash=authorization.authorization_hash(),
        timestamp=1500,
        deleted=False,
    )

    assert not verify_purge_record(
        authorization,
        record,
        transition=FakeTransition(),
    )
