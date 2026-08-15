"""Lease revocation and purge authorization for SecureChat swarms."""

from __future__ import annotations

from dataclasses import dataclass

from .rotation import SwarmRotation
from .transition import SwarmTransition


@dataclass(frozen=True)
class PurgeAuthorization:
    """Deterministic authorization for a peer to purge old swarm pieces."""

    swarm_id: str
    peer_id: str
    rotation_id: str
    revoked_piece_indices: tuple[int, ...]
    created_at: int

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")
        if not self.peer_id:
            raise ValueError("peer_id cannot be empty")
        if not self.rotation_id:
            raise ValueError("rotation_id cannot be empty")
        if self.created_at < 0:
            raise ValueError("created_at cannot be negative")

        if any(index < 0 for index in self.revoked_piece_indices):
            raise ValueError("piece indices cannot be negative")

        if len(set(self.revoked_piece_indices)) != len(
            self.revoked_piece_indices
        ):
            raise ValueError("duplicate revoked piece indices")

    @property
    def has_pieces_to_purge(self) -> bool:
        return bool(self.revoked_piece_indices)


def create_purge_authorizations(
    *,
    previous_rotation: SwarmRotation,
    next_rotation: SwarmRotation,
    transition: SwarmTransition,
    created_at: int,
) -> tuple[PurgeAuthorization, ...]:
    """Create purge authorizations for peers losing pieces."""

    if previous_rotation.swarm_id != next_rotation.swarm_id:
        raise ValueError("rotations belong to different swarms")

    if transition.swarm_id != previous_rotation.swarm_id:
        raise ValueError("transition belongs to a different swarm")

    if (
        transition.previous_rotation_id
        != previous_rotation.rotation_id
    ):
        raise ValueError("transition does not match previous rotation")

    if transition.next_rotation_id != next_rotation.rotation_id:
        raise ValueError("transition does not match next rotation")

    if created_at < 0:
        raise ValueError("created_at cannot be negative")

    previous = {
        piece: peer
        for peer, pieces in previous_rotation.assignments
        for piece in pieces
    }

    current = {
        piece: peer
        for peer, pieces in next_rotation.assignments
        for piece in pieces
    }

    revoked: dict[str, list[int]] = {}

    for piece, old_peer in previous.items():
        new_peer = current.get(piece)

        if new_peer != old_peer:
            revoked.setdefault(old_peer, []).append(piece)

    authorizations = []

    for peer_id in sorted(revoked):
        authorizations.append(
            PurgeAuthorization(
                swarm_id=previous_rotation.swarm_id,
                peer_id=peer_id,
                rotation_id=next_rotation.rotation_id,
                revoked_piece_indices=tuple(sorted(revoked[peer_id])),
                created_at=created_at,
            )
        )

    return tuple(authorizations)
