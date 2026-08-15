from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class TransportAddress:
    host: str
    port: int


class Transport(ABC):
    """Common interface for SecureChat transports."""

    @abstractmethod
    def connect(self) -> None:
        """Establish the transport connection."""

    @abstractmethod
    def close(self) -> None:
        """Close the transport connection."""

    @abstractmethod
    def send(self, data: bytes) -> None:
        """Send one framed payload."""

    @abstractmethod
    def receive(self) -> bytes:
        """Receive one framed payload."""
