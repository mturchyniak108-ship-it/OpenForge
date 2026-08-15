"""Local TCP transport for SecureChat.

This transport is intentionally independent of Tor.
The same protocol frames can later be carried by an onion transport.
"""

from __future__ import annotations

import asyncio

from securechat.protocol import Message, encode_frame, decode_frame


class LocalTransport:
    """Length-prefixed TCP transport for local SecureChat testing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server: asyncio.AbstractServer | None = None

    async def start(self, handler):
        """Start the local TCP server."""
        self.server = await asyncio.start_server(
            handler,
            self.host,
            self.port,
        )

        socket = self.server.sockets[0]
        self.port = socket.getsockname()[1]

        return self

    async def stop(self):
        """Stop the local TCP server."""
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def send(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        message: Message,
    ):
        """Send one SecureChat message."""
        writer.write(encode_frame(message))
        await writer.drain()

    async def receive(
        self,
        reader: asyncio.StreamReader,
    ) -> Message:
        """Receive exactly one SecureChat message."""
        header = await reader.readexactly(4)

        length = int.from_bytes(header, "big")

        if length > 1024 * 1024:
            raise ValueError("frame exceeds maximum size")

        payload = await reader.readexactly(length)

        return decode_frame(header + payload)

    async def connect(self):
        """Connect to the configured local endpoint."""
        return await asyncio.open_connection(
            self.host,
            self.port,
        )
