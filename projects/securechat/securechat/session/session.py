"""Transport-independent SecureChat session."""

from __future__ import annotations

from enum import Enum
from typing import Any

from securechat.protocol import Message


class SessionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTED = "connected"
    CLOSED = "closed"


class SecureChatSession:
    """Application-level session over a SecureChat transport."""

    def __init__(self, transport: Any) -> None:
        self.transport = transport
        self.state = SessionState.DISCONNECTED
        self._connection: Any = None

    @property
    def connection(self) -> Any:
        return self._connection

    async def connect(self) -> Any:
        """Connect using the configured transport."""

        if self.state == SessionState.CONNECTED:
            return self._connection

        self._connection = await self.transport.connect()
        self.state = SessionState.CONNECTED
        return self._connection

    async def send(self, message: Message) -> None:
        """Send one SecureChat message."""

        self._require_connected()

        result = self.transport.send(
            self._connection,
            message,
        )

        if hasattr(result, "__await__"):
            await result

    async def receive(self) -> Message:
        """Receive one SecureChat message."""

        self._require_connected()

        result = self.transport.receive(
            self._connection,
        )

        if hasattr(result, "__await__"):
            result = await result

        return result

    async def close(self) -> None:
        """Close the underlying transport connection."""

        if self._connection is None:
            self.state = SessionState.CLOSED
            return

        result = self.transport.close(
            self._connection,
        )

        if hasattr(result, "__await__"):
            await result

        self._connection = None
        self.state = SessionState.CLOSED

    def _require_connected(self) -> None:
        if self.state != SessionState.CONNECTED:
            raise RuntimeError(
                "SecureChat session is not connected"
            )
