"""Cryptographic ownership bindings for SecureChat swarm pieces."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .piece import MessagePiece
from .rotation import SwarmRotation


@dataclass(frozen=True)
class PieceBinding:
    """Deterministic cryptographic binding of a piece to its swarm owner."""

    swarm_id: str
    rotation_id: str
    peer_id: str
    piece_index: int
    piece_hash: str

    @classmethod
    def create(
        cls,
        *,
        rotation: SwarmRotation,
        peer_id: str,
        piece: MessagePiece,
    ) -> "PieceBinding":
        """Create a binding for a piece assigned to a peer by a rotation."""

        if not peer_id:
            raise ValueError("peer_id cannot be empty")

        if piece.swarm_id != rotation.swarm_id:
            raise ValueError("piece belongs to a different swarm")

        owner = rotation.piece_owner(piece.piece_index)
        if owner != peer_id:
            raise ValueError(
                f"piece {piece.piece_index} is assigned to {owner}, not {peer_id}"
            )

        return cls(
            swarm_id=rotation.swarm_id,
            rotation_id=rotation.rotation_id,
            peer_id=peer_id,
            piece_index=piece.piece_index,
            piece_hash=piece.piece_hash,
        )

    def to_canonical_bytes(self) -> bytes:
        """Serialize the binding deterministically."""

        value = {
            "swarm_id": self.swarm_id,
            "rotation_id": self.rotation_id,
            "peer_id": self.peer_id,
            "piece_index": self.piece_index,
            "piece_hash": self.piece_hash,
        }

        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def binding_hash(self) -> str:
        """Return the deterministic SHA-256 binding hash."""

        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    def verify_piece(
        self,
        *,
        rotation: SwarmRotation,
        peer_id: str,
        piece: MessagePiece,
    ) -> bool:
        """Verify that a piece still matches this ownership binding."""

        if rotation.swarm_id != self.swarm_id:
            return False

        if rotation.rotation_id != self.rotation_id:
            return False

        if peer_id != self.peer_id:
            return False

        if piece.swarm_id != self.swarm_id:
            return False

        if piece.piece_index != self.piece_index:
            return False

        if piece.piece_hash != self.piece_hash:
            return False

        try:
            owner = rotation.piece_owner(piece.piece_index)
        except KeyError:
            return False

        return owner == self.peer_id

    def verify_hash(self, expected_hash: str) -> bool:
        """Verify the binding against an expected binding hash."""

        if not isinstance(expected_hash, str):
            return False

        return self.binding_hash() == expected_hash


def bind_piece(
    *,
    rotation: SwarmRotation,
    peer_id: str,
    piece: MessagePiece,
) -> PieceBinding:
    """Create a cryptographic ownership binding for a swarm piece."""

    return PieceBinding.create(
        rotation=rotation,
        peer_id=peer_id,
        piece=piece,
    )


def verify_piece_binding(
    binding: PieceBinding,
    *,
    rotation: SwarmRotation,
    peer_id: str,
    piece: MessagePiece,
) -> bool:
    """Verify a piece against an existing ownership binding."""

    return binding.verify_piece(
        rotation=rotation,
        peer_id=peer_id,
        piece=piece,
    )
