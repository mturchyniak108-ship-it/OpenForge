import pytest

from securechat.swarm import MessagePiece
from securechat.swarm.manifest_builder import (
    build_manifest,
    calculate_manifest_hash,
    verify_manifest,
)


def make_pieces():
    return tuple(
        MessagePiece.create(
            swarm_id="swarm-1",
            piece_index=index,
            ciphertext=(
                bytes([index]) * 16
                if index < 2
                else bytes([index]) * 8
            ),
        )
        for index in range(3)
    )


def test_build_manifest():
    pieces = make_pieces()

    manifest = build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=16,
        expires_at=1750000000,
    )

    assert manifest.swarm_id == "swarm-1"
    assert manifest.message_id == "message-1"
    assert manifest.recipient_id == "bob"
    assert manifest.piece_count == 3
    assert manifest.piece_size == 16
    assert manifest.piece_hashes == tuple(
        piece.piece_hash for piece in pieces
    )


def test_manifest_hash_is_deterministic():
    pieces = make_pieces()

    first = build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=16,
        expires_at=1750000000,
    )

    second = build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=16,
        expires_at=1750000000,
    )

    assert calculate_manifest_hash(first) == calculate_manifest_hash(second)


def test_empty_pieces_rejected():
    with pytest.raises(ValueError, match="pieces"):
        build_manifest(
            swarm_id="swarm-1",
            message_id="message-1",
            recipient_id="bob",
            pieces=(),
            piece_size=16,
            expires_at=1750000000,
        )


def test_mismatched_swarm_rejected():
    pieces = make_pieces()

    foreign = MessagePiece.create(
        swarm_id="other-swarm",
        piece_index=0,
        ciphertext=b"x" * 16,
    )

    with pytest.raises(ValueError, match="same swarm"):
        build_manifest(
            swarm_id="swarm-1",
            message_id="message-1",
            recipient_id="bob",
            pieces=(foreign,) + pieces[1:],
            piece_size=16,
            expires_at=1750000000,
        )


def test_non_contiguous_indices_rejected():
    pieces = (
        MessagePiece.create(
            swarm_id="swarm-1",
            piece_index=0,
            ciphertext=b"a" * 16,
        ),
        MessagePiece.create(
            swarm_id="swarm-1",
            piece_index=2,
            ciphertext=b"b" * 16,
        ),
    )

    with pytest.raises(ValueError, match="contiguous"):
        build_manifest(
            swarm_id="swarm-1",
            message_id="message-1",
            recipient_id="bob",
            pieces=pieces,
            piece_size=16,
            expires_at=1750000000,
        )


def test_tampered_piece_rejected():
    original = MessagePiece.create(
        swarm_id="swarm-1",
        piece_index=0,
        ciphertext=b"correct ciphertext",
    )

    tampered = MessagePiece(
        swarm_id=original.swarm_id,
        piece_index=original.piece_index,
        piece_hash=original.piece_hash,
        ciphertext=b"tampered ciphertext",
    )

    with pytest.raises(ValueError, match="integrity"):
        build_manifest(
            swarm_id="swarm-1",
            message_id="message-1",
            recipient_id="bob",
            pieces=(tampered,),
            piece_size=len(tampered.ciphertext),
            expires_at=1750000000,
        )


def test_manifest_verifies_matching_pieces():
    pieces = make_pieces()

    manifest = build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=16,
        expires_at=1750000000,
    )

    assert verify_manifest(manifest, pieces) is True


def test_manifest_rejects_wrong_piece():
    pieces = make_pieces()

    manifest = build_manifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        pieces=pieces,
        piece_size=16,
        expires_at=1750000000,
    )

    wrong = MessagePiece.create(
        swarm_id="swarm-1",
        piece_index=0,
        ciphertext=b"wrong ciphertext",
    )

    replacement = (wrong,) + pieces[1:]

    assert verify_manifest(manifest, replacement) is False
