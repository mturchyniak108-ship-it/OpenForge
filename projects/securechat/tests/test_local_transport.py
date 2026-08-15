import asyncio

from securechat.protocol import Message
from securechat.transport import LocalTransport


def test_local_transport_message_round_trip():
    async def scenario():
        received = []

        transport = LocalTransport()

        async def handler(reader, writer):
            try:
                message = await transport.receive(reader)
                received.append(message)
            finally:
                writer.close()
                await writer.wait_closed()

        await transport.start(handler)

        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            transport.port,
        )

        original = Message.create(
            sender="alice",
            recipient="bob",
            sequence=1,
            timestamp=1750000000,
            message_type="text",
            payload=b"Hello over local transport",
        )

        await transport.send(reader, writer, original)

        await asyncio.sleep(0.05)

        writer.close()
        await writer.wait_closed()

        await transport.stop()

        assert received == [original]

    asyncio.run(scenario())


def test_local_transport_binds_loopback():
    async def scenario():
        transport = LocalTransport()
        await transport.start(lambda r, w: None)

        socket = transport.server.sockets[0]
        host, port = socket.getsockname()[:2]

        await transport.stop()

        assert host == "127.0.0.1"
        assert port > 0

    asyncio.run(scenario())
