"""Deterministic cryptographic bindings for SecureChat swarm audit events."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json


@dataclass(frozen=True)
class AuditBinding:
    """Authenticated binding between a swarm audit event and protocol state."""

    swarm_id: str
    rotation_id: str
    event_type: str
    event_id: str
    actor_id: str
    created_at: int
    details: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(
        cls,
        *,
        swarm_id: str,
        rotation_id: str,
        event_type: str,
        event_id: str,
        actor_id: str,
        created_at: int,
        details: dict[str, str] | None = None,
    ) -> "AuditBinding":
        """Create and validate a deterministic audit binding."""

        if not swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if not rotation_id:
            raise ValueError("rotation_id cannot be empty")

        if not event_type:
            raise ValueError("event_type cannot be empty")

        if not event_id:
            raise ValueError("event_id cannot be empty")

        if not actor_id:
            raise ValueError("actor_id cannot be empty")

        if created_at < 0:
            raise ValueError("created_at cannot be negative")

        normalized_details = tuple(
            sorted(
                (str(key), str(value))
                for key, value in (details or {}).items()
            )
        )

        return cls(
            swarm_id=swarm_id,
            rotation_id=rotation_id,
            event_type=event_type,
            event_id=event_id,
            actor_id=actor_id,
            created_at=created_at,
            details=normalized_details,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize the binding deterministically."""

        value = {
            "actor_id": self.actor_id,
            "created_at": self.created_at,
            "details": [[key, value] for key, value in self.details],
            "event_id": self.event_id,
            "event_type": self.event_type,
            "rotation_id": self.rotation_id,
            "swarm_id": self.swarm_id,
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


def hash_audit_binding(binding: AuditBinding) -> str:
    """Return the canonical hash for an audit binding."""

    return binding.binding_hash()


def verify_audit_binding(
    binding: AuditBinding,
    expected_hash: str,
) -> bool:
    """Verify an audit binding against its expected SHA-256 hash."""

    if not expected_hash:
        return False

    return binding.binding_hash() == expected_hash
