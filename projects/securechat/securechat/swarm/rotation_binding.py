"""Cryptographic bindings for SecureChat swarm rotations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .rotation import SwarmRotation


@dataclass(frozen=True)
class RotationBinding:
    """Deterministic cryptographic binding to a complete swarm rotation."""

    swarm_id: str
    rotation_id: str
    rotation_hash: str
    created_at: int
    expires_at: int

    @classmethod
    def create(cls, *, rotation: SwarmRotation) -> "RotationBinding":
        """Create a binding for a complete swarm rotation."""

        if not rotation.swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if not rotation.rotation_id:
            raise ValueError("rotation_id cannot be empty")

        if rotation.created_at < 0:
            raise ValueError("created_at cannot be negative")

        if rotation.expires_at < 0:
            raise ValueError("expires_at cannot be negative")

        return cls(
            swarm_id=rotation.swarm_id,
            rotation_id=rotation.rotation_id,
            rotation_hash=rotation.rotation_hash(),
            created_at=rotation.created_at,
            expires_at=rotation.expires_at,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize the rotation binding deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "rotation_hash": self.rotation_hash,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
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

    def verify(self, *, rotation: SwarmRotation) -> bool:
        """Verify this binding against the complete supplied rotation."""

        if rotation.swarm_id != self.swarm_id:
            return False

        if rotation.rotation_id != self.rotation_id:
            return False

        if rotation.created_at != self.created_at:
            return False

        if rotation.expires_at != self.expires_at:
            return False

        return rotation.rotation_hash() == self.rotation_hash

    def verify_hash(self, expected_hash: str) -> bool:
        """Verify the binding against an expected binding hash."""

        if not isinstance(expected_hash, str):
            return False

        return self.binding_hash() == expected_hash


def bind_rotation(*, rotation: SwarmRotation) -> RotationBinding:
    """Create a deterministic cryptographic binding for a rotation."""

    return RotationBinding.create(rotation=rotation)


def verify_rotation_binding(
    binding: RotationBinding,
    *,
    rotation: SwarmRotation,
) -> bool:
    """Verify a rotation against an existing binding."""

    return binding.verify(rotation=rotation)
