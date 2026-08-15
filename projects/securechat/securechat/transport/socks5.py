"""Minimal SOCKS5 client for SecureChat onion transport.

The destination hostname is deliberately sent to the SOCKS5 proxy using
ATYP=DOMAINNAME. This prevents local DNS resolution of .onion addresses.
"""

from __future__ import annotations

import socket
import struct


class Socks5Error(ConnectionError):
    """Raised when a SOCKS5 operation fails."""


class Socks5Connection:
    """Small SOCKS5 CONNECT client using the standard library."""

    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        *,
        timeout: float = 10.0,
    ) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self, destination_host: str, destination_port: int) -> socket.socket:
        if not destination_host:
            raise ValueError("destination host cannot be empty")

        if not 1 <= destination_port <= 65535:
            raise ValueError("destination port must be between 1 and 65535")

        sock = socket.create_connection(
            (self.proxy_host, self.proxy_port),
            timeout=self.timeout,
        )
        self.sock = sock

        try:
            self._negotiate()
            self._connect_domain(destination_host, destination_port)
            return sock
        except Exception:
            sock.close()
            self.sock = None
            raise

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def _read_exact(self, size: int) -> bytes:
        if self.sock is None:
            raise Socks5Error("SOCKS5 connection is not open")

        data = bytearray()

        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise Socks5Error("SOCKS5 proxy closed the connection")
            data.extend(chunk)

        return bytes(data)

    def _negotiate(self) -> None:
        assert self.sock is not None

        # SOCKS version 5, one authentication method, NO AUTH.
        self.sock.sendall(b"\x05\x01\x00")

        response = self._read_exact(2)

        if response[0] != 0x05:
            raise Socks5Error("proxy did not respond as SOCKS5")

        if response[1] != 0x00:
            raise Socks5Error(
                f"SOCKS5 authentication method rejected: 0x{response[1]:02x}"
            )

    def _connect_domain(self, host: str, port: int) -> None:
        assert self.sock is not None

        host_bytes = host.encode("idna")

        if len(host_bytes) > 255:
            raise ValueError("destination hostname is too long")

        request = (
            b"\x05"          # SOCKS5
            b"\x01"          # CONNECT
            b"\x00"          # reserved
            b"\x03"          # DOMAINNAME -- proxy resolves it
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", port)
        )

        self.sock.sendall(request)

        header = self._read_exact(4)

        if header[0] != 0x05:
            raise Socks5Error("invalid SOCKS5 response version")

        reply = header[1]

        if reply != 0x00:
            raise Socks5Error(
                f"SOCKS5 CONNECT failed: 0x{reply:02x}"
            )

        address_type = header[3]

        if address_type == 0x01:
            self._read_exact(4)
        elif address_type == 0x03:
            length = self._read_exact(1)[0]
            self._read_exact(length)
        elif address_type == 0x04:
            self._read_exact(16)
        else:
            raise Socks5Error(
                f"unknown SOCKS5 address type: 0x{address_type:02x}"
            )

        self._read_exact(2)
