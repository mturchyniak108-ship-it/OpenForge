import pytest

from securechat.swarm.receipt import DeliveryReceipt
from securechat.swarm.receipt_binding import (
    ReceiptBinding,
    hash_receipt,
    verify_receipt_binding,
)


def make_receipt():
    return DeliveryReceipt(
        swarm_id="swarm-1",
        peer_id="peer-1",
        piece_index=3,
        delivered_at=1200,
    )


def make_binding():
    receipt = make_receipt()

    return ReceiptBinding.create(
        swarm_id="swarm-1",
        rotation_id="rotation-1",
        piece_index=3,
        peer_id="peer-1",
        receipt=receipt,
        created_at=1250,
    )


def test_receipt_binding_creation():
    binding = make_binding()

    assert binding.swarm_id == "swarm-1"
    assert binding.rotation_id == "rotation-1"
    assert binding.piece_index == 3
    assert binding.peer_id == "peer-1"
    assert len(binding.receipt_hash) == 64
    assert binding.created_at == 1250


def test_receipt_hash_is_deterministic():
    first = make_receipt()
    second = make_receipt()

    assert hash_receipt(first) == hash_receipt(second)


def test_binding_hash_is_deterministic():
    first = make_binding()
    second = make_binding()

    assert first.binding_hash() == second.binding_hash()


def test_matching_receipt_verifies():
    binding = make_binding()

    assert binding.verify_receipt(make_receipt())
    assert verify_receipt_binding(binding, make_receipt())


def test_wrong_swarm_rejected():
    binding = make_binding()

    receipt = DeliveryReceipt(
        swarm_id="swarm-2",
        peer_id="peer-1",
        piece_index=3,
        delivered_at=1200,
    )

    assert not binding.verify_receipt(receipt)


def test_wrong_piece_rejected():
    binding = make_binding()

    receipt = DeliveryReceipt(
        swarm_id="swarm-1",
        peer_id="peer-1",
        piece_index=4,
        delivered_at=1200,
    )

    assert not binding.verify_receipt(receipt)


def test_wrong_peer_rejected():
    binding = make_binding()

    receipt = DeliveryReceipt(
        swarm_id="swarm-1",
        peer_id="peer-2",
        piece_index=3,
        delivered_at=1200,
    )

    assert not binding.verify_receipt(receipt)


def test_modified_receipt_rejected():
    binding = make_binding()

    receipt = DeliveryReceipt(
        swarm_id="swarm-1",
        peer_id="peer-1",
        piece_index=3,
        delivered_at=1201,
    )

    assert not binding.verify_receipt(receipt)


def test_wrong_swarm_creation_rejected():
    with pytest.raises(ValueError, match="swarm_id"):
        ReceiptBinding.create(
            swarm_id="swarm-2",
            rotation_id="rotation-1",
            piece_index=3,
            peer_id="peer-1",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_wrong_piece_creation_rejected():
    with pytest.raises(ValueError, match="piece_index"):
        ReceiptBinding.create(
            swarm_id="swarm-1",
            rotation_id="rotation-1",
            piece_index=4,
            peer_id="peer-1",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_wrong_peer_creation_rejected():
    with pytest.raises(ValueError, match="peer_id"):
        ReceiptBinding.create(
            swarm_id="swarm-1",
            rotation_id="rotation-1",
            piece_index=3,
            peer_id="peer-2",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_empty_swarm_rejected():
    with pytest.raises(ValueError, match="swarm_id"):
        ReceiptBinding.create(
            swarm_id="",
            rotation_id="rotation-1",
            piece_index=3,
            peer_id="peer-1",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_empty_rotation_rejected():
    with pytest.raises(ValueError, match="rotation_id"):
        ReceiptBinding.create(
            swarm_id="swarm-1",
            rotation_id="",
            piece_index=3,
            peer_id="peer-1",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_negative_piece_rejected():
    with pytest.raises(ValueError, match="piece_index"):
        ReceiptBinding.create(
            swarm_id="swarm-1",
            rotation_id="rotation-1",
            piece_index=-1,
            peer_id="peer-1",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_empty_peer_rejected():
    with pytest.raises(ValueError, match="peer_id"):
        ReceiptBinding.create(
            swarm_id="swarm-1",
            rotation_id="rotation-1",
            piece_index=3,
            peer_id="",
            receipt=make_receipt(),
            created_at=1250,
        )


def test_negative_created_at_rejected():
    with pytest.raises(ValueError, match="created_at"):
        ReceiptBinding.create(
            swarm_id="swarm-1",
            rotation_id="rotation-1",
            piece_index=3,
            peer_id="peer-1",
            receipt=make_receipt(),
            created_at=-1,
        )


def test_different_rotation_changes_binding_hash():
    receipt = make_receipt()

    first = ReceiptBinding.create(
        swarm_id="swarm-1",
        rotation_id="rotation-1",
        piece_index=3,
        peer_id="peer-1",
        receipt=receipt,
        created_at=1250,
    )

    second = ReceiptBinding.create(
        swarm_id="swarm-1",
        rotation_id="rotation-2",
        piece_index=3,
        peer_id="peer-1",
        receipt=receipt,
        created_at=1250,
    )

    assert first.binding_hash() != second.binding_hash()


def test_different_creation_time_changes_binding_hash():
    receipt = make_receipt()

    first = ReceiptBinding.create(
        swarm_id="swarm-1",
        rotation_id="rotation-1",
        piece_index=3,
        peer_id="peer-1",
        receipt=receipt,
        created_at=1250,
    )

    second = ReceiptBinding.create(
        swarm_id="swarm-1",
        rotation_id="rotation-1",
        piece_index=3,
        peer_id="peer-1",
        receipt=receipt,
        created_at=1251,
    )

    assert first.binding_hash() != second.binding_hash()


def test_canonical_bytes_are_stable():
    binding = make_binding()

    assert binding.to_canonical_bytes() == binding.to_canonical_bytes()


def test_receipt_hash_is_sha256():
    digest = hash_receipt(make_receipt())

    assert len(digest) == 64
    assert all(char in "0123456789abcdef" for char in digest)
