"""Seeder rotation and allocation for SecureChat dead-drop swarms."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math

from .manifest import DeadDropManifest
from .lease import SwarmLease


MAX_ALLOCATION = 0.05


@dataclass(frozen=True)
class SwarmRotation:
    """A complete assignment of encrypted pieces to swarm seeders."""

    swarm_id: str
    rotation_id: str
    previous_rotation_id: str | None
    assignments: tuple[tuple[str, tuple[int, ...]], ...]
    created_at: int
    expires_at: int

    @classmethod
    def create(
        cls,
        *,
        manifest: DeadDropManifest,
        rotation_id: str,
        assignments: dict[str, tuple[int, ...] | list[int]],
        created_at: int,
        expires_at: int,
        previous_rotation_id: str | None = None,
    ) -> "SwarmRotation":
        """Create and validate a complete swarm piece assignment."""

        if not rotation_id:
            raise ValueError("rotation_id cannot be empty")

        if created_at < 0:
            raise ValueError("created_at cannot be negative")

        if expires_at < 0:
            raise ValueError("expires_at cannot be negative")

        if expires_at and expires_at <= created_at:
            raise ValueError("expires_at must be after created_at")

        if previous_rotation_id == rotation_id:
            raise ValueError("rotation cannot reference itself")

        if not assignments:
            raise ValueError("assignments cannot be empty")

        if manifest.piece_count < 20:
            raise ValueError(
                "manifest must contain at least 20 pieces for a 5% allocation limit"
            )

        max_pieces = math.floor(manifest.piece_count * MAX_ALLOCATION)

        if max_pieces < 1:
            raise ValueError("manifest is too small for a 5% allocation")

        normalized: list[tuple[str, tuple[int, ...]]] = []
        seen: set[int] = set()

        for peer_id, raw_indices in sorted(assignments.items()):
            if not peer_id:
                raise ValueError("peer_id cannot be empty")

            indices = tuple(sorted(raw_indices))

            if not indices:
                raise ValueError(
                    f"peer {peer_id} must have at least one assigned piece"
                )

            # Validate duplicate indices within this peer first.
            if len(set(indices)) != len(indices):
                raise ValueError(
                    f"peer {peer_id} contains duplicate piece indices"
                )

            # Validate range and global ownership before allocation.
            for index in indices:
                if index < 0 or index >= manifest.piece_count:
                    raise ValueError(
                        f"piece index {index} is outside the manifest"
                    )

                if index in seen:
                    raise ValueError(
                        f"piece {index} is assigned to more than one peer"
                    )

            # Only after ownership has been established do we enforce
            # the per-peer 5% allocation ceiling.
            if len(indices) > max_pieces:
                raise ValueError(
                    f"peer {peer_id} exceeds the 5% piece allocation limit"
                )

            seen.update(indices)
            normalized.append((peer_id, indices))

        expected = set(range(manifest.piece_count))

        if seen != expected:
            missing = sorted(expected - seen)
            raise ValueError(
                f"rotation does not assign every piece; missing={missing}"
            )

        return cls(
            swarm_id=manifest.swarm_id,
            rotation_id=rotation_id,
            previous_rotation_id=previous_rotation_id,
            assignments=tuple(normalized),
            created_at=created_at,
            expires_at=expires_at,
        )

    def is_expired(self, now: int) -> bool:
        """Return whether this rotation has expired."""

        if now < 0:
            raise ValueError("now cannot be negative")

        return self.expires_at != 0 and now >= self.expires_at

    def lease_for_peer(self, peer_id: str) -> SwarmLease:
        """Create the peer's lease from this rotation."""

        for assigned_peer, indices in self.assignments:
            if assigned_peer == peer_id:
                return SwarmLease(
                    swarm_id=self.swarm_id,
                    peer_id=peer_id,
                    piece_indices=indices,
                    allocation_limit=MAX_ALLOCATION,
                    expires_at=self.expires_at,
                )

        raise KeyError(
            f"peer is not assigned in this rotation: {peer_id}"
        )

    def piece_owner(self, piece_index: int) -> str:
        """Return the peer currently assigned to a piece."""

        if piece_index < 0:
            raise ValueError("piece_index cannot be negative")

        for peer_id, indices in self.assignments:
            if piece_index in indices:
                return peer_id

        raise KeyError(f"piece is not assigned: {piece_index}")

    def to_canonical_bytes(self) -> bytes:
        """Serialize rotation metadata deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "previous_rotation_id": self.previous_rotation_id,
            "assignments": [
                [peer_id, list(indices)]
                for peer_id, indices in self.assignments
            ],
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def rotation_hash(self) -> str:
        """Return a deterministic hash of rotation metadata."""

        return hashlib.sha256(
            self.to_canonical_bytes()
        ).hexdigest()


def rotate(
    *,
    manifest: DeadDropManifest,
    rotation_id: str,
    assignments: dict[str, tuple[int, ...] | list[int]],
    created_at: int,
    expires_at: int,
    previous_rotation: SwarmRotation | None = None,
) -> SwarmRotation:
    """Create a new rotation chained to the previous rotation."""

    previous_id = (
        previous_rotation.rotation_id
        if previous_rotation is not None
        else None
    )

    if previous_rotation is not None:
        if previous_rotation.swarm_id != manifest.swarm_id:
            raise ValueError(
                "previous rotation belongs to another swarm"
            )

        # Expiration is inclusive: at expires_at the old rotation
        # is no longer valid and cannot be rotated forward.
        if previous_rotation.is_expired(created_at):
            raise ValueError(
                "previous rotation has already expired"
            )

    return SwarmRotation.create(
        manifest=manifest,
        rotation_id=rotation_id,
        assignments=assignments,
        created_at=created_at,
        expires_at=expires_at,
        previous_rotation_id=previous_id,
    )
