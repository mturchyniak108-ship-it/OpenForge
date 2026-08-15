"""Deterministic cryptographic binding for swarm delivery receipts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .receipt import DeliveryReceipt


@dataclass(frozen=True)
class ReceiptBinding:
    """Bind a delivery receipt to its swarm and rotation context."""

    swarm_id: str
    rotation_id: str
    piece_index: int
    peer_id: str
    receipt_hash: str
    created_at: int

    @classmethod
    def create(
        cls,
        *,
        swarm_id: str,
        rotation_id: str,
        piece_index: int,
        peer_id: str,
        receipt: DeliveryReceipt,
        created_at: int,
    ) -> "ReceiptBinding":
        """Create a deterministic binding for a delivery receipt."""

        if not swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if not rotation_id:
            raise ValueError("rotation_id cannot be empty")

        if piece_index < 0:
            raise ValueError("piece_index cannot be negative")

        if not peer_id:
            raise ValueError("peer_id cannot be empty")

        if created_at < 0:
            raise ValueError("created_at cannot be negative")

        if receipt.swarm_id != swarm_id:
            raise ValueError("receipt swarm_id does not match binding")

        if receipt.piece_index != piece_index:
            raise ValueError("receipt piece_index does not match binding")

        if receipt.peer_id != peer_id:
            raise ValueError("receipt peer_id does not match binding")

        receipt_hash = _receipt_hash(receipt)

        return cls(
            swarm_id=swarm_id,
            rotation_id=rotation_id,
            piece_index=piece_index,
            peer_id=peer_id,
            receipt_hash=receipt_hash,
            created_at=created_at,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize binding metadata deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "piece_index": self.piece_index,
            "peer_id": self.peer_id,
            "receipt_hash": self.receipt_hash,
            "created_at": self.created_at,
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def binding_hash(self) -> str:
        """Return the deterministic SHA-256 binding hash."""

        return hashlib.sha256(
            self.to_canonical_bytes()
        ).hexdigest()

    def verify_receipt(self, receipt: DeliveryReceipt) -> bool:
        """Verify that a receipt matches this binding."""

        if receipt.swarm_id != self.swarm_id:
            return False

        if receipt.piece_index != self.piece_index:
            return False

        if receipt.peer_id != self.peer_id:
            return False

        return _receipt_hash(receipt) == self.receipt_hash


def _receipt_hash(receipt: DeliveryReceipt) -> str:
    """Hash the receipt's canonical representation."""

    canonical = receipt.to_canonical_bytes()

    return hashlib.sha256(canonical).hexdigest()


def hash_receipt(receipt: DeliveryReceipt) -> str:
    """Return the deterministic SHA-256 hash of a delivery receipt."""

    return _receipt_hash(receipt)


def verify_receipt_binding(
    binding: ReceiptBinding,
    receipt: DeliveryReceipt,
) -> bool:
    """Return whether a receipt matches an existing binding."""

    return binding.verify_receipt(receipt)
