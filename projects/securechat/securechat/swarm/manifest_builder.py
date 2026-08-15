"""Construction and verification of SecureChat dead-drop manifests."""

from __future__ import annotations

import hashlib
import json

from .manifest import DeadDropManifest
from .piece import MessagePiece


def build_manifest(
    *,
    swarm_id: str,
    message_id: str,
    recipient_id: str,
    pieces: tuple[MessagePiece, ...] | list[MessagePiece],
    expires_at: int,
    piece_size: int | None = None,
) -> DeadDropManifest:
    """Build a manifest from a complete ordered collection of encrypted pieces."""

    if not pieces:
        raise ValueError("pieces cannot be empty")

    pieces = tuple(pieces)

    if not swarm_id:
        raise ValueError("swarm_id cannot be empty")

    if not message_id:
        raise ValueError("message_id cannot be empty")

    if not recipient_id:
        raise ValueError("recipient_id cannot be empty")

    if expires_at < 0:
        raise ValueError("expires_at cannot be negative")

    for expected_index, piece in enumerate(pieces):
        if not isinstance(piece, MessagePiece):
            raise TypeError("all pieces must be MessagePiece instances")

        if piece.swarm_id != swarm_id:
            raise ValueError("all pieces must belong to the same swarm")

        if piece.piece_index != expected_index:
            raise ValueError("piece indices must be contiguous starting at zero")

        if not piece.verify():
            raise ValueError(
                f"piece {piece.piece_index} failed integrity verification"
            )

    if piece_size is None:
        piece_size = max(len(piece.ciphertext) for piece in pieces)

    if piece_size <= 0:
        raise ValueError("piece_size must be positive")

    for piece in pieces[:-1]:
        if len(piece.ciphertext) != piece_size:
            raise ValueError("all non-final pieces must have the configured piece size")

    if len(pieces[-1].ciphertext) > piece_size:
        raise ValueError("final piece exceeds configured piece size")

    return DeadDropManifest(
        swarm_id=swarm_id,
        message_id=message_id,
        recipient_id=recipient_id,
        piece_count=len(pieces),
        piece_size=piece_size,
        piece_hashes=tuple(piece.piece_hash for piece in pieces),
        expires_at=expires_at,
    )


def manifest_to_canonical_bytes(manifest: DeadDropManifest) -> bytes:
    """Serialize public manifest metadata deterministically."""

    value = {
        "version": manifest.version,
        "swarm_id": manifest.swarm_id,
        "message_id": manifest.message_id,
        "recipient_id": manifest.recipient_id,
        "piece_count": manifest.piece_count,
        "piece_size": manifest.piece_size,
        "piece_hashes": list(manifest.piece_hashes),
        "expires_at": manifest.expires_at,
    }

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def calculate_manifest_hash(manifest: DeadDropManifest) -> str:
    """Calculate the canonical SHA-256 hash of manifest metadata."""

    return hashlib.sha256(
        manifest_to_canonical_bytes(manifest)
    ).hexdigest()


def verify_manifest(
    manifest: DeadDropManifest,
    pieces: tuple[MessagePiece, ...] | list[MessagePiece],
) -> bool:
    """Verify that pieces exactly match the manifest."""

    pieces = tuple(pieces)

    if len(pieces) != manifest.piece_count:
        return False

    for expected_index, piece in enumerate(pieces):
        if not isinstance(piece, MessagePiece):
            return False

        if piece.swarm_id != manifest.swarm_id:
            return False

        if piece.piece_index != expected_index:
            return False

        if not piece.verify():
            return False

        if piece.piece_hash != manifest.piece_hashes[expected_index]:
            return False

        if expected_index < manifest.piece_count - 1:
            if len(piece.ciphertext) != manifest.piece_size:
                return False
        elif len(piece.ciphertext) > manifest.piece_size:
            return False

    return True
