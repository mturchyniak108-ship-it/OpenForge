"""Seeder allocation leases for dead-drop swarms."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SwarmLease:
    """Authorization for a peer to hold specific encrypted pieces."""

    swarm_id: str
    peer_id: str
    piece_indices: tuple[int, ...]
    allocation_limit: float = 0.05
    expires_at: int = 0

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")
        if not self.peer_id:
            raise ValueError("peer_id cannot be empty")
        if not 0 < self.allocation_limit <= 0.05:
            raise ValueError("allocation_limit must be greater than 0 and at most 5%")
        if any(index < 0 for index in self.piece_indices):
            raise ValueError("piece indices cannot be negative")
        if self.expires_at < 0:
            raise ValueError("expires_at cannot be negative")
