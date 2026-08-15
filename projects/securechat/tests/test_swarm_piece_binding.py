import pytest

from securechat.swarm import MessagePiece
from securechat.swarm.manifest_builder import build_manifest
from securechat.swarm.piece_binding import (
    PieceBinding,
    bind_piece,
    verify_piece_binding,
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


def make_piece(index=7):
    return MessagePiece.create(
        swarm_id="swarm-1",
        piece_index=index,
        ciphertext=bytes([index]) * 32,
    )


def test_binding_creation():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = PieceBinding.create(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert binding.swarm_id == "swarm-1"
    assert binding.rotation_id == "rotation-1"
    assert binding.peer_id == "peer-7"
    assert binding.piece_index == 7
    assert binding.piece_hash == piece.piece_hash


def test_binding_rejects_wrong_peer():
    rotation = make_rotation()
    piece = make_piece(7)

    with pytest.raises(ValueError, match="assigned"):
        PieceBinding.create(
            rotation=rotation,
            peer_id="peer-8",
            piece=piece,
        )


def test_binding_rejects_wrong_swarm():
    rotation = make_rotation()

    piece = MessagePiece.create(
        swarm_id="other-swarm",
        piece_index=7,
        ciphertext=b"x" * 32,
    )

    with pytest.raises(ValueError, match="different swarm"):
        PieceBinding.create(
            rotation=rotation,
            peer_id="peer-7",
            piece=piece,
        )


def test_binding_rejects_empty_peer():
    rotation = make_rotation()
    piece = make_piece(7)

    with pytest.raises(ValueError, match="peer_id"):
        PieceBinding.create(
            rotation=rotation,
            peer_id="",
            piece=piece,
        )


def test_binding_is_deterministic():
    rotation = make_rotation()
    piece = make_piece(7)

    first = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    second = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert first == second
    assert first.to_canonical_bytes() == second.to_canonical_bytes()
    assert first.binding_hash() == second.binding_hash()


def test_canonical_bytes_are_stable():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert binding.to_canonical_bytes() == binding.to_canonical_bytes()


def test_binding_hash_is_sha256_length():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert len(binding.binding_hash()) == 64
    assert all(
        character in "0123456789abcdef"
        for character in binding.binding_hash()
    )


def test_binding_hash_verification():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert binding.verify_hash(binding.binding_hash())
    assert not binding.verify_hash("0" * 64)


def test_piece_verification_succeeds():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert binding.verify_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )


def test_helper_verification_succeeds():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert verify_piece_binding(
        binding,
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )


def test_wrong_peer_fails_verification():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert not binding.verify_piece(
        rotation=rotation,
        peer_id="peer-8",
        piece=piece,
    )


def test_wrong_rotation_fails_verification():
    manifest = make_manifest()

    assignments = {
        f"peer-{index}": (index,)
        for index in range(20)
    }

    rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-1",
        assignments=assignments,
        created_at=1000,
        expires_at=1500,
    )

    other_rotation = SwarmRotation.create(
        manifest=manifest,
        rotation_id="rotation-2",
        assignments=assignments,
        created_at=1500,
        expires_at=2000,
    )

    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert not binding.verify_piece(
        rotation=other_rotation,
        peer_id="peer-7",
        piece=piece,
    )


def test_wrong_piece_index_fails_verification():
    rotation = make_rotation()

    piece = make_piece(7)
    other_piece = make_piece(8)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert not binding.verify_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=other_piece,
    )


def test_wrong_piece_hash_fails_verification():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    tampered = MessagePiece(
        swarm_id="swarm-1",
        piece_index=7,
        piece_hash="0" * 64,
        ciphertext=piece.ciphertext,
    )

    assert not binding.verify_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=tampered,
    )


def test_wrong_swarm_fails_verification():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    foreign_piece = MessagePiece(
        swarm_id="other-swarm",
        piece_index=7,
        piece_hash=piece.piece_hash,
        ciphertext=piece.ciphertext,
    )

    assert not binding.verify_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=foreign_piece,
    )


def test_tampered_binding_hash_is_detected():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert not binding.verify_hash("f" * 64)


def test_binding_preserves_piece_hash():
    rotation = make_rotation()
    piece = make_piece(7)

    binding = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece,
    )

    assert binding.piece_hash == piece.piece_hash


def test_each_peer_gets_distinct_binding():
    rotation = make_rotation()

    piece_a = make_piece(7)
    piece_b = make_piece(8)

    binding_a = bind_piece(
        rotation=rotation,
        peer_id="peer-7",
        piece=piece_a,
    )

    binding_b = bind_piece(
        rotation=rotation,
        peer_id="peer-8",
        piece=piece_b,
    )

    assert binding_a.binding_hash() != binding_b.binding_hash()
