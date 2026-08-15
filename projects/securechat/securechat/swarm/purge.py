"""Dead-drop purge records."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PurgeRecord:
    """Signed acknowledgement that a swarm peer purged its pieces."""

    swarm_id: str
    peer_id: str
    receipt_hash: str
    timestamp: int
    deleted: bool

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")
        if not self.peer_id:
            raise ValueError("peer_id cannot be empty")
        if not self.receipt_hash:
            raise ValueError("receipt_hash cannot be empty")
        if self.timestamp < 0:
            raise ValueError("timestamp cannot be negative")
