"""Authenticated metadata for transitions between swarm rotations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .rotation import SwarmRotation


@dataclass(frozen=True)
class SwarmTransition:
    """Deterministic record describing a rotation handoff."""

    swarm_id: str
    previous_rotation_id: str
    next_rotation_id: str
    revoked_peers: tuple[str, ...]
    granted_peers: tuple[str, ...]
    moved_pieces: tuple[tuple[int, str, str], ...]
    created_at: int

    @classmethod
    def create(
        cls,
        *,
        previous_rotation: SwarmRotation,
        next_rotation: SwarmRotation,
        created_at: int,
    ) -> "SwarmTransition":
        """Create a transition between two rotations."""

        if previous_rotation.swarm_id != next_rotation.swarm_id:
            raise ValueError("rotations belong to different swarms")

        if previous_rotation.rotation_id == next_rotation.rotation_id:
            raise ValueError("transition requires different rotations")

        if created_at < 0:
            raise ValueError("created_at cannot be negative")

        if created_at < previous_rotation.created_at:
            raise ValueError(
                "transition cannot occur before previous rotation"
            )

        if created_at < next_rotation.created_at:
            raise ValueError(
                "transition cannot occur before next rotation"
            )

        if (
            next_rotation.previous_rotation_id is not None
            and next_rotation.previous_rotation_id
            != previous_rotation.rotation_id
        ):
            raise ValueError(
                "next rotation does not reference previous rotation"
            )

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

        previous_peers = set(previous.values())
        current_peers = set(current.values())

        revoked_peers = tuple(
            sorted(previous_peers - current_peers)
        )

        granted_peers = tuple(
            sorted(current_peers - previous_peers)
        )

        moved_pieces = tuple(
            sorted(
                (
                    piece,
                    previous[piece],
                    current[piece],
                )
                for piece in previous
                if previous[piece] != current[piece]
            )
        )

        return cls(
            swarm_id=previous_rotation.swarm_id,
            previous_rotation_id=previous_rotation.rotation_id,
            next_rotation_id=next_rotation.rotation_id,
            revoked_peers=revoked_peers,
            granted_peers=granted_peers,
            moved_pieces=moved_pieces,
            created_at=created_at,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize transition metadata deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "previous_rotation_id": self.previous_rotation_id,
            "next_rotation_id": self.next_rotation_id,
            "revoked_peers": list(self.revoked_peers),
            "granted_peers": list(self.granted_peers),
            "moved_pieces": [
                [piece, old_peer, new_peer]
                for piece, old_peer, new_peer in self.moved_pieces
            ],
            "created_at": self.created_at,
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def transition_hash(self) -> str:
        """Return a deterministic SHA-256 transition hash."""

        return hashlib.sha256(
            self.to_canonical_bytes()
        ).hexdigest()
