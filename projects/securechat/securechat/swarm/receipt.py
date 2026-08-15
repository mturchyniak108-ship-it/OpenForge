"""Dead-drop delivery receipts."""

from __future__ import annotations

from dataclasses import dataclass
import json


@dataclass(frozen=True)
class DeliveryReceipt:
    """Recipient acknowledgement after successful reconstruction.

    The receipt supports both the original message-level receipt schema and
    swarm piece-level binding metadata.  The latter is optional so existing
    callers remain compatible.
    """

    swarm_id: str
    message_id: str = ""
    recipient_id: str = ""
    manifest_hash: str = ""
    verified: bool = False
    timestamp: int = 0
    signature: bytes = b""

    # Piece-level binding metadata.
    peer_id: str = ""
    piece_index: int = -1
    delivered_at: int | None = None

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if self.message_id == "" and self.piece_index < 0:
            raise ValueError(
                "receipt requires message_id or piece_index"
            )

        if self.recipient_id == "" and self.peer_id == "":
            raise ValueError(
                "receipt requires recipient_id or peer_id"
            )

        if self.manifest_hash == "" and self.piece_index < 0:
            raise ValueError(
                "receipt requires manifest_hash or piece_index"
            )

        if self.timestamp < 0:
            raise ValueError("timestamp cannot be negative")

        if self.delivered_at is not None and self.delivered_at < 0:
            raise ValueError("delivered_at cannot be negative")

        if self.piece_index < -1:
            raise ValueError("piece_index cannot be negative")

        if not isinstance(self.signature, bytes):
            raise TypeError("signature must be bytes")

    def to_canonical_bytes(self) -> bytes:
        """Serialize the complete receipt deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "message_id": self.message_id,
            "recipient_id": self.recipient_id,
            "manifest_hash": self.manifest_hash,
            "verified": self.verified,
            "timestamp": self.timestamp,
            "signature": self.signature.hex(),
            "peer_id": self.peer_id,
            "piece_index": self.piece_index,
            "delivered_at": self.delivered_at,
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def effective_delivery_time(self) -> int:
        """Return piece delivery time when present, otherwise receipt time."""

        if self.delivered_at is not None:
            return self.delivered_at
        return self.timestamp
