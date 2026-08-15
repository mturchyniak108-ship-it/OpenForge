import pytest

from securechat.swarm import (
    DeadDropManifest,
    DeliveryReceipt,
    MessagePiece,
    PurgeRecord,
    SwarmLease,
)


def test_manifest_creation():
    manifest = DeadDropManifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        piece_count=2,
        piece_size=1024,
        piece_hashes=("hash-a", "hash-b"),
        expires_at=1750000000,
    )

    assert manifest.piece_count == 2
    assert len(manifest.piece_hashes) == 2


def test_manifest_requires_matching_piece_hashes():
    with pytest.raises(ValueError, match="piece_hashes"):
        DeadDropManifest(
            swarm_id="swarm-1",
            message_id="message-1",
            recipient_id="bob",
            piece_count=2,
            piece_size=1024,
            piece_hashes=("hash-a",),
            expires_at=1750000000,
        )


def test_message_piece_requires_bytes():
    with pytest.raises(TypeError, match="bytes"):
        MessagePiece(
            swarm_id="swarm-1",
            piece_index=0,
            piece_hash="hash",
            ciphertext="not bytes",
        )


def test_lease_enforces_five_percent_limit():
    with pytest.raises(ValueError, match="5%"):
        SwarmLease(
            swarm_id="swarm-1",
            peer_id="peer-1",
            piece_indices=(1,),
            allocation_limit=0.06,
        )


def test_lease_accepts_five_percent_limit():
    lease = SwarmLease(
        swarm_id="swarm-1",
        peer_id="peer-1",
        piece_indices=(1, 5),
        allocation_limit=0.05,
        expires_at=1750000000,
    )

    assert lease.allocation_limit == 0.05


def test_delivery_receipt():
    receipt = DeliveryReceipt(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        manifest_hash="manifest-hash",
        verified=True,
        timestamp=1750000000,
        signature=b"signature",
    )

    assert receipt.verified is True


def test_purge_record():
    record = PurgeRecord(
        swarm_id="swarm-1",
        peer_id="peer-1",
        receipt_hash="receipt-hash",
        timestamp=1750000000,
        deleted=True,
    )

    assert record.deleted is True


def test_piece_hash_verification():
    from securechat.swarm import hash_piece, verify_piece

    ciphertext = b"encrypted piece"
    piece = MessagePiece(
        swarm_id="swarm-1",
        piece_index=0,
        piece_hash=hash_piece(
            MessagePiece(
                swarm_id="swarm-1",
                piece_index=0,
                piece_hash="temporary",
                ciphertext=ciphertext,
            )
        ),
        ciphertext=ciphertext,
    )

    assert verify_piece(piece)


def test_tampered_piece_fails_hash_verification():
    from securechat.swarm import verify_piece

    piece = MessagePiece(
        swarm_id="swarm-1",
        piece_index=0,
        piece_hash="00" * 32,
        ciphertext=b"encrypted piece",
    )

    assert not verify_piece(piece)


def test_manifest_hash_is_deterministic():
    from securechat.swarm import hash_manifest

    manifest = DeadDropManifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        piece_count=20,
        piece_size=1024,
        piece_hashes=tuple(f"hash-{i}" for i in range(20)),
        expires_at=1750000000,
    )

    assert hash_manifest(manifest) == hash_manifest(manifest)


def test_piece_matches_manifest():
    from securechat.swarm import hash_piece
    from securechat.swarm import verify_piece_against_manifest

    ciphertext = b"encrypted piece"
    piece_hash = hash_piece(
        MessagePiece(
            swarm_id="swarm-1",
            piece_index=0,
            piece_hash="temporary",
            ciphertext=ciphertext,
        )
    )

    manifest = DeadDropManifest(
        swarm_id="swarm-1",
        message_id="message-1",
        recipient_id="bob",
        piece_count=20,
        piece_size=1024,
        piece_hashes=(piece_hash,) + tuple(
            f"hash-{i}" for i in range(1, 20)
        ),
        expires_at=1750000000,
    )

    piece = MessagePiece(
        swarm_id="swarm-1",
        piece_index=0,
        piece_hash=piece_hash,
        ciphertext=ciphertext,
    )

    assert verify_piece_against_manifest(manifest, piece)


def test_piece_wrong_manifest_is_rejected():
    from securechat.swarm import hash_piece
    from securechat.swarm import verify_piece_against_manifest

    ciphertext = b"encrypted piece"
    piece_hash = hash_piece(
        MessagePiece(
            swarm_id="swarm-1",
            piece_index=0,
            piece_hash="temporary",
            ciphertext=ciphertext,
        )
    )

    manifest = DeadDropManifest(
        swarm_id="different-swarm",
        message_id="message-1",
        recipient_id="bob",
        piece_count=20,
        piece_size=1024,
        piece_hashes=(piece_hash,) + tuple(
            f"hash-{i}" for i in range(1, 20)
        ),
        expires_at=1750000000,
    )

    piece = MessagePiece(
        swarm_id="swarm-1",
        piece_index=0,
        piece_hash=piece_hash,
        ciphertext=ciphertext,
    )

    assert not verify_piece_against_manifest(manifest, piece)


def test_swarm_policy_allows_exactly_five_percent():
    from securechat.swarm import SwarmPolicy

    policy = SwarmPolicy()

    assert policy.maximum_pieces_per_peer(100) == 5

    policy.validate_allocation(
        100,
        (0, 1, 2, 3, 4),
    )


def test_swarm_policy_rejects_more_than_five_percent():
    from securechat.swarm import SwarmPolicy

    policy = SwarmPolicy()

    with pytest.raises(ValueError, match="5%"):
        policy.validate_allocation(
            100,
            (0, 1, 2, 3, 4, 5),
        )


def test_swarm_policy_requires_twenty_pieces():
    from securechat.swarm import SwarmPolicy

    policy = SwarmPolicy()

    with pytest.raises(ValueError, match="20"):
        policy.maximum_pieces_per_peer(19)


def test_swarm_policy_rejects_duplicate_piece_indices():
    from securechat.swarm import SwarmPolicy

    policy = SwarmPolicy()

    with pytest.raises(ValueError, match="duplicate"):
        policy.validate_allocation(
            100,
            (1, 1, 2),
        )


def test_swarm_policy_rejects_invalid_piece_indices():
    from securechat.swarm import SwarmPolicy

    policy = SwarmPolicy()

    with pytest.raises(ValueError, match="invalid"):
        policy.validate_allocation(
            100,
            (0, 1, 100),
        )


def test_message_piece_create_calculates_hash():
    piece = MessagePiece.create(
        swarm_id="swarm-1",
        piece_index=0,
        ciphertext=b"encrypted payload",
    )

    assert piece.piece_hash == MessagePiece.calculate_hash(
        b"encrypted payload"
    )
    assert piece.verify() is True


def test_message_piece_detects_tampered_ciphertext():
    piece = MessagePiece.create(
        swarm_id="swarm-1",
        piece_index=0,
        ciphertext=b"encrypted payload",
    )

    tampered = MessagePiece(
        swarm_id=piece.swarm_id,
        piece_index=piece.piece_index,
        piece_hash=piece.piece_hash,
        ciphertext=b"tampered payload",
    )

    assert tampered.verify() is False


def test_message_piece_detects_wrong_hash():
    piece = MessagePiece(
        swarm_id="swarm-1",
        piece_index=0,
        piece_hash="0" * 64,
        ciphertext=b"encrypted payload",
    )

    assert piece.verify() is False


def test_message_piece_hash_is_deterministic():
    ciphertext = bytes(range(256))

    assert (
        MessagePiece.calculate_hash(ciphertext)
        == MessagePiece.calculate_hash(ciphertext)
    )


def test_different_ciphertext_produces_different_hash():
    assert (
        MessagePiece.calculate_hash(b"payload-a")
        != MessagePiece.calculate_hash(b"payload-b")
    )


def test_empty_ciphertext_is_supported():
    piece = MessagePiece.create(
        swarm_id="swarm-1",
        piece_index=0,
        ciphertext=b"",
    )

    assert piece.verify() is True
