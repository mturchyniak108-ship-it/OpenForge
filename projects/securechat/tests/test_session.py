import asyncio

import pytest

from securechat.protocol import Message
from securechat.session import SecureChatSession, SessionState


class FakeTransport:
    """Minimal transport used to test session behavior."""

    def __init__(self):
        self.connected = False
        self.closed = False
        self.messages = []

    async def connect(self):
        self.connected = True
        return object()

    async def send(self, connection, message):
        assert self.connected
        self.messages.append(message)

    async def receive(self, connection):
        assert self.connected
        return self.messages[-1]

    async def close(self, connection):
        self.connected = False
        self.closed = True


def make_message():
    return Message.create(
        sender="alice",
        recipient="bob",
        sequence=1,
        timestamp=1750000000,
        message_type="chat",
        payload=b"hello",
    )


def test_initial_state():
    session = SecureChatSession(FakeTransport())

    assert session.state == SessionState.DISCONNECTED
    assert session.connection is None


def test_connect_changes_state():
    async def run():
        transport = FakeTransport()
        session = SecureChatSession(transport)

        connection = await session.connect()

        assert connection is session.connection
        assert session.state == SessionState.CONNECTED
        assert transport.connected

    asyncio.run(run())


def test_connect_is_idempotent():
    async def run():
        transport = FakeTransport()
        session = SecureChatSession(transport)

        first = await session.connect()
        second = await session.connect()

        assert first is second
        assert session.state == SessionState.CONNECTED

    asyncio.run(run())


def test_send_and_receive():
    async def run():
        transport = FakeTransport()
        session = SecureChatSession(transport)

        await session.connect()

        message = make_message()

        await session.send(message)
        received = await session.receive()

        assert received == message

    asyncio.run(run())


def test_send_requires_connection():
    async def run():
        session = SecureChatSession(FakeTransport())

        with pytest.raises(RuntimeError, match="not connected"):
            await session.send(make_message())

    asyncio.run(run())


def test_receive_requires_connection():
    async def run():
        session = SecureChatSession(FakeTransport())

        with pytest.raises(RuntimeError, match="not connected"):
            await session.receive()

    asyncio.run(run())


def test_close_changes_state():
    async def run():
        transport = FakeTransport()
        session = SecureChatSession(transport)

        await session.connect()
        await session.close()

        assert session.state == SessionState.CLOSED
        assert session.connection is None
        assert transport.closed

    asyncio.run(run())


def test_close_is_safe_when_disconnected():
    async def run():
        session = SecureChatSession(FakeTransport())

        await session.close()

        assert session.state == SessionState.CLOSED
        assert session.connection is None

    asyncio.run(run())


def test_full_session_lifecycle():
    async def run():
        transport = FakeTransport()
        session = SecureChatSession(transport)

        assert session.state == SessionState.DISCONNECTED

        await session.connect()
        assert session.state == SessionState.CONNECTED

        message = make_message()
        await session.send(message)

        received = await session.receive()

        assert received == message

        await session.close()

        assert session.state == SessionState.CLOSED

    asyncio.run(run())
