"""Encrypted dead-drop swarm manifest."""

from __future__ import annotations

from dataclasses import dataclass

SWARM_PROTOCOL_VERSION = 1


@dataclass(frozen=True)
class DeadDropManifest:
    """Public metadata describing an encrypted dead-drop swarm."""

    swarm_id: str
    message_id: str
    recipient_id: str
    piece_count: int
    piece_size: int
    piece_hashes: tuple[str, ...]
    expires_at: int
    version: int = SWARM_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")
        if not self.message_id:
            raise ValueError("message_id cannot be empty")
        if not self.recipient_id:
            raise ValueError("recipient_id cannot be empty")
        if self.piece_count <= 0:
            raise ValueError("piece_count must be positive")
        if self.piece_size <= 0:
            raise ValueError("piece_size must be positive")
        if len(self.piece_hashes) != self.piece_count:
            raise ValueError("piece_hashes must match piece_count")
        if self.expires_at < 0:
            raise ValueError("expires_at cannot be negative")
