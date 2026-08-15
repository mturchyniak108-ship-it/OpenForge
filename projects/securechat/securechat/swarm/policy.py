"""Allocation policy for SecureChat dead-drop swarms."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SwarmPolicy:
    """Enforce the maximum amount of a swarm held by one peer."""

    allocation_limit: float = 0.05
    minimum_piece_count: int = 20

    def maximum_pieces_per_peer(self, piece_count: int) -> int:
        """Return the largest permitted number of pieces for one peer."""
        if piece_count < self.minimum_piece_count:
            raise ValueError(
                f"swarm must contain at least {self.minimum_piece_count} pieces"
            )

        maximum = int(piece_count * self.allocation_limit)

        # For a 5% policy this deliberately allows exactly 5%.
        if maximum < 1:
            raise ValueError("swarm is too small for the allocation policy")

        return maximum

    def validate_allocation(
        self,
        piece_count: int,
        piece_indices: tuple[int, ...] | list[int],
    ) -> None:
        """Validate one peer's complete piece allocation."""
        indices = tuple(piece_indices)

        if len(indices) != len(set(indices)):
            raise ValueError("peer cannot hold more than one copy of the same piece: duplicate piece indices")

        maximum = self.maximum_pieces_per_peer(piece_count)

        for index in indices:
            if index < 0 or index >= piece_count:
                raise ValueError(f"invalid piece index: {index}")

        if len(indices) > maximum:
            raise ValueError(
                f"allocation exceeds the 5% limit: maximum {maximum} pieces"
            )
