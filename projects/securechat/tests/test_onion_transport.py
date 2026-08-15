import pytest

from securechat.transport.onion import (
    OnionEndpoint,
    OnionTransport,
    TorProxy,
)


ONION = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"


def test_onion_endpoint_accepts_v3_address():
    endpoint = OnionEndpoint(ONION, 9000)

    assert endpoint.address == (ONION, 9000)


def test_onion_endpoint_normalizes_host():
    endpoint = OnionEndpoint(ONION.upper(), 9000)

    assert endpoint.host == ONION


def test_onion_endpoint_rejects_invalid_host():
    with pytest.raises(ValueError):
        OnionEndpoint("example.com", 9000)


def test_onion_endpoint_rejects_invalid_port():
    with pytest.raises(ValueError):
        OnionEndpoint(ONION, 0)


def test_tor_proxy_defaults():
    proxy = TorProxy()

    assert proxy.address == ("127.0.0.1", 9050)


def test_onion_transport_configuration():
    endpoint = OnionEndpoint(ONION, 9000)
    proxy = TorProxy("127.0.0.1", 9050)
    transport = OnionTransport(endpoint, proxy)

    assert transport.destination == (ONION, 9000)
    assert transport.proxy_address == ("127.0.0.1", 9050)


def test_onion_transport_description_contains_no_secrets():
    transport = OnionTransport(OnionEndpoint(ONION, 9000))

    description = transport.describe()

    assert description["transport"] == "tor-onion"
    assert description["protocol"] == "socks5"
    assert description["destination"] == (ONION, 9000)


def test_onion_transport_has_framed_message_api():
    from securechat.transport import OnionEndpoint, OnionTransport

    transport = OnionTransport(
        OnionEndpoint(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            9000,
        )
    )

    assert callable(transport.send)
    assert callable(transport.receive)


def test_onion_transport_end_to_end_with_fake_socks5():
    import socket
    import threading

    from securechat.protocol import Message
    from securechat.transport import (
        OnionEndpoint,
        OnionTransport,
        TorProxy,
    )

    received = {}

    def fake_socks5():
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        received["port"] = server.getsockname()[1]
        ready.set()

        conn, _ = server.accept()

        try:
            # SOCKS5 greeting.
            greeting = conn.recv(3)
            assert greeting == b"\x05\x01\x00"
            conn.sendall(b"\x05\x00")

            # SOCKS5 CONNECT request.
            header = conn.recv(4)
            assert header[:4] == b"\x05\x01\x00\x03"

            hostname_length = conn.recv(1)[0]
            hostname = conn.recv(hostname_length).decode()
            port_bytes = conn.recv(2)

            received["hostname"] = hostname
            received["destination_port"] = int.from_bytes(port_bytes, "big")

            # Successful SOCKS5 CONNECT response.
            conn.sendall(
                b"\x05\x00\x00\x01"
                b"\x7f\x00\x00\x01"
                b"\x00\x01"
            )

            # Receive SecureChat frame.
            frame_header = conn.recv(4)
            length = int.from_bytes(frame_header, "big")
            payload = conn.recv(length)

            received["frame"] = frame_header + payload

            # Echo the frame back.
            conn.sendall(frame_header + payload)

        finally:
            conn.close()
            server.close()

    ready = threading.Event()

    thread = threading.Thread(
        target=fake_socks5,
        daemon=True,
    )
    thread.start()
    ready.wait(timeout=2)

    endpoint = OnionEndpoint(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
        9000,
    )

    transport = OnionTransport(
        endpoint,
        TorProxy("127.0.0.1", received["port"]),
    )

    sock = transport.connect()

    try:
        message = Message.create(
            sender="alice",
            recipient="bob",
            sequence=1,
            timestamp=1750000000,
            message_type="text",
            payload=b"hello through onion transport",
        )

        transport.send(sock, message)
        result = transport.receive(sock)

        assert result == message
        assert result.message_type == "text"
        assert result.payload == b"hello through onion transport"

        assert (
            received["hostname"]
            == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
        )

        assert received["destination_port"] == 9000

    finally:
        transport.close()
        thread.join(timeout=2)
