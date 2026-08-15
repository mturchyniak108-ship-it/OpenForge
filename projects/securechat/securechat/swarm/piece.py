"""Encrypted dead-drop message pieces with cryptographic integrity."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class MessagePiece:
    """One encrypted, independently verifiable message piece."""

    swarm_id: str
    piece_index: int
    piece_hash: str
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not self.swarm_id:
            raise ValueError("swarm_id cannot be empty")

        if self.piece_index < 0:
            raise ValueError("piece_index cannot be negative")

        if not self.piece_hash:
            raise ValueError("piece_hash cannot be empty")

        if not isinstance(self.ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

    @staticmethod
    def calculate_hash(ciphertext: bytes) -> str:
        """Calculate the canonical SHA-256 hash of ciphertext."""
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")

        return hashlib.sha256(ciphertext).hexdigest()

    @classmethod
    def create(
        cls,
        swarm_id: str,
        piece_index: int,
        ciphertext: bytes,
    ) -> "MessagePiece":
        """Create a piece and calculate its integrity hash."""
        return cls(
            swarm_id=swarm_id,
            piece_index=piece_index,
            piece_hash=cls.calculate_hash(ciphertext),
            ciphertext=ciphertext,
        )

    def verify(self) -> bool:
        """Verify that the ciphertext matches its recorded hash."""
        return self.calculate_hash(self.ciphertext) == self.piece_hash
