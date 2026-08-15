"""Tor onion-service transport for SecureChat.

Tor itself remains an external process. SecureChat connects to the
configured SOCKS5 proxy and sends the .onion hostname to that proxy
as a SOCKS5 DOMAINNAME, preventing local DNS resolution.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import socket

from securechat.protocol import Message, encode_frame, decode_frame
from .socks5 import Socks5Connection


_ONION_RE = re.compile(
    r"^(?:[a-z2-7]{56}\.onion|localhost|127\.0\.0\.1)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class OnionEndpoint:
    """A SecureChat endpoint reachable through a Tor SOCKS proxy."""

    host: str
    port: int

    def __post_init__(self) -> None:
        host = self.host.strip().lower()

        if not _ONION_RE.fullmatch(host):
            raise ValueError(
                "host must be a valid v3 .onion address or local test host"
            )

        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")

        object.__setattr__(self, "host", host)

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port


@dataclass(frozen=True)
class TorProxy:
    """SOCKS5 proxy used to reach an onion endpoint."""

    host: str = "127.0.0.1"
    port: int = 9050

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("proxy host cannot be empty")

        if not 1 <= self.port <= 65535:
            raise ValueError("proxy port must be between 1 and 65535")

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port


class OnionTransport:
    """SecureChat transport over a Tor SOCKS5 proxy."""

    def __init__(
        self,
        endpoint: OnionEndpoint,
        proxy: TorProxy | None = None,
        *,
        timeout: float = 10.0,
    ) -> None:
        self.endpoint = endpoint
        self.proxy = proxy or TorProxy()
        self.timeout = timeout
        self.connection: Socks5Connection | None = None

    @property
    def destination(self) -> tuple[str, int]:
        return self.endpoint.address

    @property
    def proxy_address(self) -> tuple[str, int]:
        return self.proxy.address

    def describe(self) -> dict[str, object]:
        """Return non-secret transport metadata."""
        return {
            "transport": "tor-onion",
            "destination": self.destination,
            "proxy": self.proxy_address,
            "protocol": "socks5",
        }

    def connect(self) -> socket.socket:
        """Connect to the onion endpoint through the SOCKS5 proxy."""
        connection = Socks5Connection(
            self.proxy.host,
            self.proxy.port,
            timeout=self.timeout,
        )

        sock = connection.connect(
            self.endpoint.host,
            self.endpoint.port,
        )

        self.connection = connection
        return sock

    def send(self, sock: socket.socket, message: Message) -> None:
        """Send one length-prefixed SecureChat message."""
        sock.sendall(encode_frame(message))

    def receive(self, sock: socket.socket) -> Message:
        """Receive exactly one length-prefixed SecureChat message."""
        header = self._read_exact(sock, 4)
        length = int.from_bytes(header, "big")

        if length > 1024 * 1024:
            raise ValueError("frame exceeds maximum size")

        payload = self._read_exact(sock, length)
        return decode_frame(header + payload)

    @staticmethod
    def _read_exact(sock: socket.socket, size: int) -> bytes:
        data = bytearray()

        while len(data) < size:
            chunk = sock.recv(size - len(data))

            if not chunk:
                raise ConnectionError("connection closed while reading frame")

            data.extend(chunk)

        return bytes(data)

    def close(self) -> None:
        """Close the active SOCKS5 connection."""
        if self.connection is not None:
            self.connection.close()
            self.connection = None
