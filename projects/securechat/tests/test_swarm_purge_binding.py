import pytest

from securechat.swarm.purge_auth import PurgeAuthorization
from securechat.swarm.purge_binding import (
    PurgeBinding,
    create_purge_binding,
    verify_purge_binding,
)


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


def make_binding(**overrides):
    authorization = make_authorization()

    values = {
        "swarm_id": authorization.swarm_id,
        "rotation_id": authorization.rotation_id,
        "rotation_hash": "rotation-hash",
        "peer_id": authorization.peer_id,
        "piece_indices": authorization.piece_indices,
        "transition_hash": authorization.transition_hash,
        "authorization_hash": authorization.authorization_hash(),
    }
    values.update(overrides)

    return PurgeBinding(**values)


def test_binding_creation():
    binding = make_binding()

    assert binding.swarm_id == "swarm-1"
    assert binding.rotation_id == "rotation-2"
    assert binding.rotation_hash == "rotation-hash"
    assert binding.peer_id == "peer-1"
    assert binding.piece_indices == (0, 1)


def test_binding_hash_is_deterministic():
    first = make_binding()
    second = make_binding()

    assert first.to_canonical_bytes() == second.to_canonical_bytes()
    assert first.binding_hash() == second.binding_hash()


def test_binding_rejects_empty_rotation_hash():
    with pytest.raises(ValueError, match="rotation_hash"):
        make_binding(rotation_hash="")


def test_binding_rejects_empty_peer_id():
    with pytest.raises(ValueError, match="peer_id"):
        make_binding(peer_id="")


def test_binding_rejects_negative_piece_index():
    with pytest.raises(ValueError, match="negative"):
        make_binding(piece_indices=(-1,))


def test_binding_rejects_duplicate_piece_indices():
    with pytest.raises(ValueError, match="duplicates"):
        make_binding(piece_indices=(0, 0))


def test_binding_matches_authorization():
    authorization = make_authorization()
    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    assert binding.matches_authorization(authorization)


def test_binding_verifies():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    assert verify_purge_binding(
        binding,
        authorization=authorization,
        rotation_hash="rotation-hash",
    )


def test_wrong_rotation_hash_is_rejected():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    assert not verify_purge_binding(
        binding,
        authorization=authorization,
        rotation_hash="different-rotation-hash",
    )


def test_tampered_binding_rotation_hash_is_rejected():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    tampered = PurgeBinding(
        swarm_id=binding.swarm_id,
        rotation_id=binding.rotation_id,
        rotation_hash="tampered",
        peer_id=binding.peer_id,
        piece_indices=binding.piece_indices,
        transition_hash=binding.transition_hash,
        authorization_hash=binding.authorization_hash,
    )

    assert not verify_purge_binding(
        tampered,
        authorization=authorization,
        rotation_hash="rotation-hash",
    )


def test_tampered_peer_is_rejected():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    tampered = PurgeBinding(
        swarm_id=binding.swarm_id,
        rotation_id=binding.rotation_id,
        rotation_hash=binding.rotation_hash,
        peer_id="peer-attacker",
        piece_indices=binding.piece_indices,
        transition_hash=binding.transition_hash,
        authorization_hash=binding.authorization_hash,
    )

    assert not verify_purge_binding(
        tampered,
        authorization=authorization,
        rotation_hash="rotation-hash",
    )


def test_tampered_piece_set_is_rejected():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    tampered = PurgeBinding(
        swarm_id=binding.swarm_id,
        rotation_id=binding.rotation_id,
        rotation_hash=binding.rotation_hash,
        peer_id=binding.peer_id,
        piece_indices=(0,),
        transition_hash=binding.transition_hash,
        authorization_hash=binding.authorization_hash,
    )

    assert not verify_purge_binding(
        tampered,
        authorization=authorization,
        rotation_hash="rotation-hash",
    )


def test_tampered_transition_hash_is_rejected():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    tampered = PurgeBinding(
        swarm_id=binding.swarm_id,
        rotation_id=binding.rotation_id,
        rotation_hash=binding.rotation_hash,
        peer_id=binding.peer_id,
        piece_indices=binding.piece_indices,
        transition_hash="tampered-transition",
        authorization_hash=binding.authorization_hash,
    )

    assert not verify_purge_binding(
        tampered,
        authorization=authorization,
        rotation_hash="rotation-hash",
    )


def test_tampered_authorization_is_rejected():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    modified_authorization = make_authorization(
        piece_indices=(0,),
    )

    assert not verify_purge_binding(
        binding,
        authorization=modified_authorization,
        rotation_hash="rotation-hash",
    )


def test_different_authorization_signature_changes_authorization_hash():
    first = make_authorization(signature=b"signature-a")
    second = make_authorization(signature=b"signature-b")

    assert first.authorization_hash() == second.authorization_hash()


def test_binding_authorization_hash_tracks_authorization_metadata():
    authorization = make_authorization()

    binding = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    assert binding.authorization_hash == authorization.authorization_hash()


def test_binding_canonical_bytes_are_stable():
    authorization = make_authorization()

    first = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    second = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-hash",
    )

    assert first.to_canonical_bytes() == second.to_canonical_bytes()


def test_different_rotation_hash_changes_binding_hash():
    authorization = make_authorization()

    first = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-a",
    )

    second = create_purge_binding(
        authorization=authorization,
        rotation_hash="rotation-b",
    )

    assert first.binding_hash() != second.binding_hash()
