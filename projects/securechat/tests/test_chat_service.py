import asyncio

import pytest

from securechat.chat import ChatService
from securechat.protocol import Message


class FakeSession:
    def __init__(self):
        self.connected = False
        self.closed = False
        self.sent = []
        self.incoming = []

    async def connect(self):
        self.connected = True
        return "connection"

    async def send(self, message):
        assert self.connected
        self.sent.append(message)

    async def receive(self):
        assert self.connected
        return self.incoming.pop(0)

    async def close(self):
        self.connected = False
        self.closed = True


def message():
    return Message.create(
        sender="alice",
        recipient="bob",
        sequence=0,
        timestamp=1750000000,
        message_type="text",
        payload=b"hello",
    )


def test_empty_sender_rejected():
    with pytest.raises(ValueError):
        ChatService(FakeSession(), sender="", recipient="bob")


def test_empty_recipient_rejected():
    with pytest.raises(ValueError):
        ChatService(FakeSession(), sender="alice", recipient="")


def test_start():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        assert await service.start() == "connection"
        assert session.connected
    asyncio.run(run())


def test_send_text():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        await service.start()
        sent = await service.send_text("hello", timestamp=1750000000)
        assert sent.sender == "alice"
        assert sent.recipient == "bob"
        assert sent.sequence == 0
        assert sent.message_type == "text"
        assert sent.payload == b"hello"
        assert session.sent == [sent]
    asyncio.run(run())


def test_sequence_increments():
    async def run():
        service = ChatService(FakeSession(), sender="alice", recipient="bob")
        await service.start()
        first = await service.send_text("one", timestamp=1)
        second = await service.send_text("two", timestamp=2)
        assert first.sequence == 0
        assert second.sequence == 1
        assert service.sequence == 2
    asyncio.run(run())


def test_unicode_text():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        await service.start()
        sent = await service.send_text("Hello 👋 世界", timestamp=1)
        assert sent.payload.decode("utf-8") == "Hello 👋 世界"
    asyncio.run(run())


def test_empty_text_rejected():
    async def run():
        service = ChatService(FakeSession(), sender="alice", recipient="bob")
        with pytest.raises(ValueError):
            await service.send_text("")
    asyncio.run(run())


def test_non_string_rejected():
    async def run():
        service = ChatService(FakeSession(), sender="alice", recipient="bob")
        with pytest.raises(TypeError):
            await service.send_text(123)
    asyncio.run(run())


def test_receive_text():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        await service.start()
        session.incoming.append(Message.create(
            sender="bob",
            recipient="alice",
            sequence=0,
            timestamp=1,
            message_type="text",
            payload="hello 👋".encode("utf-8"),
        ))
        assert await service.receive_text() == "hello 👋"
    asyncio.run(run())


def test_receive_rejects_invalid_message():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        await service.start()
        session.incoming.append("invalid")
        with pytest.raises(TypeError):
            await service.receive()
    asyncio.run(run())


def test_receive_text_rejects_non_text():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        await service.start()
        session.incoming.append(Message.create(
            sender="bob",
            recipient="alice",
            sequence=0,
            timestamp=1,
            message_type="system",
            payload=b"status",
        ))
        with pytest.raises(ValueError):
            await service.receive_text()
    asyncio.run(run())


def test_close():
    async def run():
        session = FakeSession()
        service = ChatService(session, sender="alice", recipient="bob")
        await service.start()
        await service.close()
        assert session.closed
        assert not session.connected
    asyncio.run(run())
