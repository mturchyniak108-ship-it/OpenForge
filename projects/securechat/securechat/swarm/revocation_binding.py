"""Cryptographic bindings for SecureChat swarm peer revocations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .rotation import SwarmRotation


@dataclass(frozen=True)
class RevocationBinding:
    """Deterministic binding of a peer revocation to a swarm rotation."""

    swarm_id: str
    rotation_id: str
    peer_id: str
    revoked_at: int
    reason: str

    @classmethod
    def create(
        cls,
        *,
        rotation: SwarmRotation,
        peer_id: str,
        revoked_at: int,
        reason: str,
    ) -> "RevocationBinding":
        """Create a revocation binding for a peer in a rotation."""

        if not peer_id:
            raise ValueError("peer_id cannot be empty")

        if peer_id not in {
            assigned_peer
            for assigned_peer, _ in rotation.assignments
        }:
            raise ValueError(
                f"peer is not assigned in this rotation: {peer_id}"
            )

        if revoked_at < 0:
            raise ValueError("revoked_at cannot be negative")

        if not reason:
            raise ValueError("reason cannot be empty")

        return cls(
            swarm_id=rotation.swarm_id,
            rotation_id=rotation.rotation_id,
            peer_id=peer_id,
            revoked_at=revoked_at,
            reason=reason,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize the revocation binding deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "peer_id": self.peer_id,
            "revoked_at": self.revoked_at,
            "reason": self.reason,
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

    def verify(
        self,
        *,
        rotation: SwarmRotation,
        peer_id: str,
    ) -> bool:
        """Verify that this binding belongs to the supplied rotation and peer."""

        if rotation.swarm_id != self.swarm_id:
            return False

        if rotation.rotation_id != self.rotation_id:
            return False

        if peer_id != self.peer_id:
            return False

        return any(
            assigned_peer == self.peer_id
            for assigned_peer, _ in rotation.assignments
        )

    def verify_hash(self, expected_hash: str) -> bool:
        """Verify this binding against an expected binding hash."""

        if not isinstance(expected_hash, str):
            return False

        return self.binding_hash() == expected_hash


def bind_revocation(
    *,
    rotation: SwarmRotation,
    peer_id: str,
    revoked_at: int,
    reason: str,
) -> RevocationBinding:
    """Create a deterministic peer revocation binding."""

    return RevocationBinding.create(
        rotation=rotation,
        peer_id=peer_id,
        revoked_at=revoked_at,
        reason=reason,
    )


def verify_revocation_binding(
    binding: RevocationBinding,
    *,
    rotation: SwarmRotation,
    peer_id: str,
) -> bool:
    """Verify a revocation binding against a rotation and peer."""

    return binding.verify(
        rotation=rotation,
        peer_id=peer_id,
    )
