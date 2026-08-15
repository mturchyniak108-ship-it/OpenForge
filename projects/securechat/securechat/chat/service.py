"""Application-level SecureChat message service."""

from __future__ import annotations

import time
from typing import Any

from securechat.protocol import Message
from securechat.session import SecureChatSession


class ChatService:
    """High-level chat API built on SecureChatSession."""

    def __init__(
        self,
        session: SecureChatSession,
        *,
        sender: str,
        recipient: str,
    ) -> None:
        if not sender.strip():
            raise ValueError("sender cannot be empty")
        if not recipient.strip():
            raise ValueError("recipient cannot be empty")

        self.session = session
        self.sender = sender
        self.recipient = recipient
        self._sequence = 0

    @property
    def sequence(self) -> int:
        """Return the next outbound sequence number."""
        return self._sequence

    async def start(self) -> Any:
        """Start the underlying chat session."""
        return await self.session.connect()

    async def send_text(
        self,
        text: str,
        *,
        timestamp: int | None = None,
    ) -> Message:
        """Create and send one text message."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        if not text:
            raise ValueError("text cannot be empty")

        message = Message.create(
            sender=self.sender,
            recipient=self.recipient,
            sequence=self._sequence,
            timestamp=int(time.time()) if timestamp is None else int(timestamp),
            message_type="text",
            payload=text.encode("utf-8"),
        )

        await self.session.send(message)
        self._sequence += 1
        return message

    async def receive(self) -> Message:
        """Receive and validate one message."""
        message = await self.session.receive()
        if not isinstance(message, Message):
            raise TypeError("session returned an invalid message")
        return message

    async def receive_text(self) -> str:
        """Receive and decode one text message."""
        message = await self.receive()
        if message.message_type != "text":
            raise ValueError(f"unsupported message type: {message.message_type}")
        try:
            return message.payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("text message payload is not valid UTF-8") from exc

    async def close(self) -> None:
        """Close the underlying chat session."""
        await self.session.close()
