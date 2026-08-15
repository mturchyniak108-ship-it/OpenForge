"""Integrity helpers for SecureChat dead-drop swarm pieces."""

from __future__ import annotations

import hashlib
import json

from .manifest import DeadDropManifest
from .piece import MessagePiece


def hash_piece(piece: MessagePiece) -> str:
    """Return the canonical SHA-256 hash of a piece ciphertext."""
    return hashlib.sha256(piece.ciphertext).hexdigest()


def verify_piece(piece: MessagePiece) -> bool:
    """Verify a piece against its embedded piece hash."""
    return hash_piece(piece) == piece.piece_hash


def hash_manifest(manifest: DeadDropManifest) -> str:
    """Return a deterministic SHA-256 hash of manifest metadata."""
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
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_piece_against_manifest(
    manifest: DeadDropManifest,
    piece: MessagePiece,
) -> bool:
    """Verify swarm identity, index, and ciphertext hash against a manifest."""
    if piece.swarm_id != manifest.swarm_id:
        return False

    if piece.piece_index >= manifest.piece_count:
        return False

    expected = manifest.piece_hashes[piece.piece_index]

    if piece.piece_hash != expected:
        return False

    return verify_piece(piece)
