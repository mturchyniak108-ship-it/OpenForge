"""Authenticated purge authorization for SecureChat dead-drop swarms.

This module authorizes a peer to purge only the pieces assigned to that peer
by a specific authenticated swarm transition.

It intentionally does not perform filesystem or network deletion.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .purge import PurgeRecord
from .transition_auth import AuthenticatedTransition


@dataclass(frozen=True)
class PurgeAuthorization:
    """Signed authorization permitting a peer to purge assigned pieces."""

    swarm_id: str
    rotation_id: str
    peer_id: str
    piece_indices: tuple[int, ...]
    transition_hash: str
    timestamp: int
    signature: bytes

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if not self.rotation_id:
            raise ValueError("rotation_id cannot be empty")

        if not self.peer_id:
            raise ValueError("peer_id cannot be empty")

        if not self.transition_hash:
            raise ValueError("transition_hash cannot be empty")

        if self.timestamp < 0:
            raise ValueError("timestamp cannot be negative")

        if not isinstance(self.signature, bytes):
            raise TypeError("signature must be bytes")

        if any(index < 0 for index in self.piece_indices):
            raise ValueError("piece indices cannot be negative")

        if len(set(self.piece_indices)) != len(self.piece_indices):
            raise ValueError("piece_indices cannot contain duplicates")

    def to_canonical_bytes(self) -> bytes:
        """Serialize authorization metadata deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "peer_id": self.peer_id,
            "piece_indices": list(self.piece_indices),
            "transition_hash": self.transition_hash,
            "timestamp": self.timestamp,
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def authorization_hash(self) -> str:
        """Return a deterministic SHA-256 hash of the authorization."""

        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def to_purge_record(self) -> PurgeRecord:
        """Create the corresponding purge record."""

        return PurgeRecord(
            swarm_id=self.swarm_id,
            peer_id=self.peer_id,
            receipt_hash=self.authorization_hash(),
            timestamp=self.timestamp,
            deleted=True,
        )


def create_purge_authorization(
    *,
    swarm_id: str,
    rotation_id: str,
    peer_id: str,
    piece_indices: tuple[int, ...] | list[int],
    transition_hash: str,
    timestamp: int,
    signature: bytes,
) -> PurgeAuthorization:
    """Create a validated purge authorization.

    Signature creation remains deliberately outside this module.  The caller
    signs ``authorization.signing_bytes()`` using the project's existing
    identity/signing implementation.
    """

    indices = tuple(sorted(piece_indices))

    authorization = PurgeAuthorization(
        swarm_id=swarm_id,
        rotation_id=rotation_id,
        peer_id=peer_id,
        piece_indices=indices,
        transition_hash=transition_hash,
        timestamp=timestamp,
        signature=signature,
    )

    return authorization


def verify_purge_authorization(
    authorization: PurgeAuthorization,
    *,
    transition: AuthenticatedTransition,
) -> bool:
    """Verify that authorization belongs to the authenticated transition."""

    if authorization.swarm_id != transition.swarm_id:
        return False

    if authorization.transition_hash != transition.transition_hash:
        return False

    if authorization.rotation_id != transition.next_rotation_id:
        return False

    if authorization.peer_id not in transition.authorized_peers:
        return False

    authorized_pieces = transition.peer_piece_indices.get(
        authorization.peer_id,
        (),
    )

    if not set(authorization.piece_indices).issubset(set(authorized_pieces)):
        return False

    if authorization.timestamp < transition.created_at:
        return False

    if transition.expires_at != 0 and authorization.timestamp >= transition.expires_at:
        return False

    return True


def verify_purge_record(
    authorization: PurgeAuthorization,
    purge_record: PurgeRecord,
    *,
    transition: AuthenticatedTransition,
) -> bool:
    """Verify that a purge record is backed by valid authorization."""

    if purge_record.swarm_id != authorization.swarm_id:
        return False

    if purge_record.peer_id != authorization.peer_id:
        return False

    if purge_record.timestamp != authorization.timestamp:
        return False

    if not purge_record.deleted:
        return False

    if purge_record.receipt_hash != authorization.authorization_hash():
        return False

    return verify_purge_authorization(
        authorization,
        transition=transition,
    )
