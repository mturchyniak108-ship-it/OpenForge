"""Cryptographic binding for SecureChat swarm rotation transitions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .rotation import SwarmRotation
from .transition import SwarmTransition


@dataclass(frozen=True)
class TransitionBinding:
    """Deterministic binding of a transition to both rotation states."""

    swarm_id: str
    previous_rotation_id: str
    previous_rotation_hash: str
    next_rotation_id: str
    next_rotation_hash: str
    transition_hash: str
    created_at: int

    @classmethod
    def create(
        cls,
        *,
        previous_rotation: SwarmRotation,
        next_rotation: SwarmRotation,
        transition: SwarmTransition,
    ) -> "TransitionBinding":
        """Create a deterministic binding for a rotation transition."""

        if previous_rotation.swarm_id != next_rotation.swarm_id:
            raise ValueError("rotations belong to different swarms")

        if transition.swarm_id != previous_rotation.swarm_id:
            raise ValueError("transition swarm_id does not match rotations")

        if (
            transition.previous_rotation_id
            != previous_rotation.rotation_id
        ):
            raise ValueError(
                "transition previous_rotation_id does not match rotation"
            )

        if transition.next_rotation_id != next_rotation.rotation_id:
            raise ValueError(
                "transition next_rotation_id does not match rotation"
            )

        if transition.created_at < 0:
            raise ValueError("transition created_at cannot be negative")

        return cls(
            swarm_id=transition.swarm_id,
            previous_rotation_id=previous_rotation.rotation_id,
            previous_rotation_hash=previous_rotation.rotation_hash(),
            next_rotation_id=next_rotation.rotation_id,
            next_rotation_hash=next_rotation.rotation_hash(),
            transition_hash=transition.transition_hash(),
            created_at=transition.created_at,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize the complete binding deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "previous_rotation_id": self.previous_rotation_id,
            "previous_rotation_hash": self.previous_rotation_hash,
            "next_rotation_id": self.next_rotation_id,
            "next_rotation_hash": self.next_rotation_hash,
            "transition_hash": self.transition_hash,
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

    def verify(
        self,
        *,
        previous_rotation: SwarmRotation,
        next_rotation: SwarmRotation,
        transition: SwarmTransition,
    ) -> bool:
        """Verify the binding against both rotations and the transition."""

        if previous_rotation.swarm_id != self.swarm_id:
            return False

        if next_rotation.swarm_id != self.swarm_id:
            return False

        if previous_rotation.rotation_id != self.previous_rotation_id:
            return False

        if next_rotation.rotation_id != self.next_rotation_id:
            return False

        if transition.swarm_id != self.swarm_id:
            return False

        if (
            transition.previous_rotation_id
            != self.previous_rotation_id
        ):
            return False

        if transition.next_rotation_id != self.next_rotation_id:
            return False

        if transition.created_at != self.created_at:
            return False

        if previous_rotation.rotation_hash() != self.previous_rotation_hash:
            return False

        if next_rotation.rotation_hash() != self.next_rotation_hash:
            return False

        return transition.transition_hash() == self.transition_hash

    def verify_hash(self, expected_hash: str) -> bool:
        """Verify this binding against an expected binding hash."""

        if not isinstance(expected_hash, str):
            return False

        return self.binding_hash() == expected_hash


def bind_transition(
    *,
    previous_rotation: SwarmRotation,
    next_rotation: SwarmRotation,
    transition: SwarmTransition,
) -> TransitionBinding:
    """Create a deterministic cryptographic transition binding."""

    return TransitionBinding.create(
        previous_rotation=previous_rotation,
        next_rotation=next_rotation,
        transition=transition,
    )


def verify_transition_binding(
    binding: TransitionBinding,
    *,
    previous_rotation: SwarmRotation,
    next_rotation: SwarmRotation,
    transition: SwarmTransition,
) -> bool:
    """Verify a transition against an existing binding."""

    return binding.verify(
        previous_rotation=previous_rotation,
        next_rotation=next_rotation,
        transition=transition,
    )
