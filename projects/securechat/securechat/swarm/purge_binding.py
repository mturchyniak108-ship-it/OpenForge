"""Cryptographic binding for SecureChat swarm purge authorizations."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .purge_auth import PurgeAuthorization


@dataclass(frozen=True)
class PurgeBinding:
    """Deterministic binding between a purge authorization and its context."""

    swarm_id: str
    rotation_id: str
    rotation_hash: str
    peer_id: str
    piece_indices: tuple[int, ...]
    transition_hash: str
    authorization_hash: str

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if not self.rotation_id:
            raise ValueError("rotation_id cannot be empty")

        if not self.rotation_hash:
            raise ValueError("rotation_hash cannot be empty")

        if not self.peer_id:
            raise ValueError("peer_id cannot be empty")

        if not self.transition_hash:
            raise ValueError("transition_hash cannot be empty")

        if not self.authorization_hash:
            raise ValueError("authorization_hash cannot be empty")

        if any(index < 0 for index in self.piece_indices):
            raise ValueError("piece indices cannot be negative")

        if len(set(self.piece_indices)) != len(self.piece_indices):
            raise ValueError("piece_indices cannot contain duplicates")

    def to_canonical_bytes(self) -> bytes:
        """Serialize the complete binding deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "rotation_hash": self.rotation_hash,
            "peer_id": self.peer_id,
            "piece_indices": list(self.piece_indices),
            "transition_hash": self.transition_hash,
            "authorization_hash": self.authorization_hash,
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

    def matches_authorization(
        self,
        authorization: PurgeAuthorization,
    ) -> bool:
        """Verify that the binding exactly matches an authorization."""

        return (
            self.swarm_id == authorization.swarm_id
            and self.rotation_id == authorization.rotation_id
            and self.peer_id == authorization.peer_id
            and self.piece_indices == tuple(
                sorted(authorization.piece_indices)
            )
            and self.transition_hash == authorization.transition_hash
            and self.authorization_hash
            == authorization.authorization_hash()
        )


def create_purge_binding(
    *,
    authorization: PurgeAuthorization,
    rotation_hash: str,
) -> PurgeBinding:
    """Create a binding from a purge authorization and rotation hash."""

    if not rotation_hash:
        raise ValueError("rotation_hash cannot be empty")

    return PurgeBinding(
        swarm_id=authorization.swarm_id,
        rotation_id=authorization.rotation_id,
        rotation_hash=rotation_hash,
        peer_id=authorization.peer_id,
        piece_indices=tuple(sorted(authorization.piece_indices)),
        transition_hash=authorization.transition_hash,
        authorization_hash=authorization.authorization_hash(),
    )


def verify_purge_binding(
    binding: PurgeBinding,
    *,
    authorization: PurgeAuthorization,
    rotation_hash: str,
) -> bool:
    """Verify a binding against an authorization and rotation hash."""

    if not rotation_hash:
        return False

    if binding.rotation_hash != rotation_hash:
        return False

    return binding.matches_authorization(authorization)
